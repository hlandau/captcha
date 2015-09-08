package captcha

import "bytes"
import "container/heap"
import "github.com/llgcode/draw2d"
import "github.com/llgcode/draw2d/draw2dimg"
import "encoding/binary"
import "encoding/base64"
import "fmt"
import "golang.org/x/crypto/nacl/secretbox"
import "image"
import "image/color"
import "image/gif"
import "io"
import "math"
import "math/rand"
import crand "crypto/rand"
import "net/http"
import "net/url"
import "regexp"
import "sort"
import "strings"
import "time"
import "github.com/hlandau/degoutils/metric"
import "io/ioutil"
import "code.google.com/p/freetype-go/freetype/truetype"
import "path/filepath"

const imageMIME = "image/gif"

var prng salsaPRNG
var prngRand *rand.Rand
var spRepl = strings.NewReplacer(" ", "")

var exInstancesCreated = metric.NewCounter("captcha.instancesCreated")
var exVerifySuccesses = metric.NewCounter("captcha.verifySuccesses")
var exVerifyFailures = metric.NewCounter("captcha.verifyFailures")
var exDecodeSuccesses = metric.NewCounter("captcha.decodeSuccesses")
var exDecodeFailures = metric.NewCounter("captcha.decodeFailures")
var exImagesGenerated = metric.NewCounter("captcha.imagesGenerated")
var exNewInstancesServed = metric.NewCounter("captcha.newInstancesServed")
var exSpentHeapInstanceCount = metric.NewCounter("captcha.spentHeapInstanceCount")

func init() {
	//draw2d.SetFontFolder(".")

	err := prng.SeedSystem()
	if err != nil {
		panic(err)
	}

	prngRand = rand.New(&prng)
}

// Deterministically expresses the parameters of a given CAPTCHA.
//
// An Instance is comprised of two parts; the code which the user is expected
// to give, and a random seed used to deterministically randomise the various
// obfuscations made upon the image.
//
// You can create this yourself, but usually you should call CreateInstance.
type Instance struct {
	// The code the user must provide.
	Code string

	// A random seed controlling the obfuscations placed upon the image.
	Seed uint64

	// The time the instance expires. Doesn't control image generation.
	Expiry time.Time

	// A nonce used for encryption of the instance and to assist its unique
	// identification.
	Nonce [24]byte

	key string
}

// Randomly generates a new instance.
func (cfg *Config) NewInstance() Instance {
	cfg.init()

	i := Instance{
		Code:   cfg.genCode(),
		Seed:   uint64(prngRand.Int63()),
		Expiry: time.Now().Add(cfg.Expiry).Round(time.Second),
	}

	prng.Read(i.Nonce[:])

	exInstancesCreated.Add(1)

	return i
}

func (cfg *Config) genCode() string {
	switch cfg.CodeType {
	case MarkovCode:
		return rstrMarkov(cfg.CodeLength, prngRand)
	case RandomCode:
		return rstr(cfg.CodeLength, prngRand)
	default:
		panic("unknown code type")
	}
}

type spentKey struct {
	key    string
	expiry time.Time
}

type spentKeyHeap []spentKey

func (h spentKeyHeap) Len() int           { return len(h) }
func (h spentKeyHeap) Less(i, j int) bool { return h[i].expiry.Before(h[j].expiry) }
func (h spentKeyHeap) Swap(i, j int)      { h[i], h[j] = h[j], h[i] }
func (h *spentKeyHeap) Push(x interface{}) {
	*h = append(*h, x.(spentKey))
}
func (h *spentKeyHeap) Pop() interface{} {
	old := *h
	n := len(old)
	x := old[n-1]
	*h = old[0 : n-1]
	return x
}

// Specifies the random string generation strategy used.
type CodeType int

const (
	MarkovCode CodeType = 0 // generate pronouncable psuedo-words (easier)
	RandomCode          = 1 // generate completely random letters (harder)
)

type Config struct {
	// How many characters may be wrong in user input?
	Leeway int // default 0

	// The number of characters in newly generated instances.
	CodeLength int // default 8

	// How are codes generated? Defaults to MarkovCode.
	CodeType CodeType

	// Controls generated images.
	Width  int
	Height int

	// Key for encrypting instances. If set to zero, one will be generated
	// automatically using the system CSPRNG.
	EncryptionKey [32]byte

	// Time before an instance expires and becomes invalid.
	Expiry time.Duration // default 1 hour

	// Used to check for spent instances. If these are nil an internal
	// cache is used which is automatically pruned of expired instances.
	//
	// If you specify these you must do the pruning yourself.
	RegisterSpentInstance func(instance *Instance) error
	CheckSpentInstance    func(instance *Instance) bool

	// Do not allow the HTTP handler to serve new instance keys
	// at $PREFIX/new.
	DisallowHandlerNew bool

	// Used to store a sorted list of spent nonces.
	spentKeyHeap spentKeyHeap

	fonts []draw2d.FontData

	inited bool
}

var fontCounter = 0

func (cfg *Config) addFont(fn string) error {
	buf, err := ioutil.ReadFile(fn)
	if err != nil {
		return err
	}

	font, err := truetype.Parse(buf)
	if err != nil {
		return err
	}

	fontCounter++
	f := draw2d.FontData{
		Name:   fmt.Sprintf("captchafont%d", fontCounter),
		Family: draw2d.FontFamilySans,
		Style:  draw2d.FontStyleNormal,
	}

	draw2d.RegisterFont(f, font)

	cfg.fonts = append(cfg.fonts, f)
	return nil
}

// Set the path to the font directory. You must call this before generating images.
func (cfg *Config) SetFontPath(path string) error {
	matches, err := filepath.Glob(filepath.Join(path, "*.ttf"))
	if err != nil {
		return err
	}

	cfg.fonts = nil
	for _, m := range matches {
		err := cfg.addFont(m)
		if err != nil {
			return err
		}
	}

	return nil
}

func (cfg *Config) init() {
	if cfg.inited {
		return
	}
	if iszero(cfg.EncryptionKey[:]) {
		crand.Read(cfg.EncryptionKey[:])
	}
	if cfg.CodeLength == 0 {
		cfg.CodeLength = 8
	}
	if cfg.Expiry == 0 {
		cfg.Expiry = 1 * time.Hour
	}
	if cfg.Width == 0 {
		cfg.Width = 200
	}
	if cfg.Height == 0 {
		cfg.Height = cfg.Width / 2
	}

	cfg.spentKeyHeap = spentKeyHeap{}
	heap.Init(&cfg.spentKeyHeap)

	cfg.inited = true
}

func iszero(b []byte) bool {
	for _, v := range b {
		if v != 0 {
			return false
		}
	}
	return true
}

// Returns a string representing an instance. This is an encrypted and
// authenticated base64-encoded binary blob. The string has no malleability by
// a third party, so it can be used to uniquely represent the instance.
// You can pass this to the client and have it pass it back when verifying the
// CAPTCHA. The encoded string contains a timestamp for tracking expiry
// and uses the encryption key specified in Config.
func (cfg *Config) Key(instance *Instance) string {
	if instance.key != "" {
		return instance.key
	}

	if iszero(instance.Nonce[:]) {
		prng.Read(instance.Nonce[:])
	}

	b := make([]byte, 8+8+1+len(instance.Code))
	binary.BigEndian.PutUint64(b[0:8], instance.Seed)
	binary.BigEndian.PutUint64(b[8:16], uint64(instance.Expiry.Unix()))
	b[16] = uint8(len(instance.Code))
	copy(b[17:], []byte(instance.Code))

	out := make([]byte, 24, len(b)+secretbox.Overhead+24)
	copy(out[0:24], instance.Nonce[:])
	out = secretbox.Seal(out, b, &instance.Nonce, &cfg.EncryptionKey)
	s := base64.URLEncoding.EncodeToString(out)
	//s = strings.TrimRight(s, "=")
	instance.key = s
	return s
}

func repadBase64(k string) string {
	for len(k)%4 != 0 {
		k += "="
	}
	return k
}

// Tries to decode an instance key. May return an error if the instance
// key is not valid or the timestamp has expired.
func (cfg *Config) decodeInstance(key string) (*Instance, error) {
	b, err := base64.URLEncoding.DecodeString(key)
	if err != nil {
		return nil, err
	}

	if len(b) < 8+8+1+secretbox.Overhead+24 {
		return nil, fmt.Errorf("invalid key")
	}

	var nonce [24]byte
	copy(nonce[:], b[0:24])

	a, ok := secretbox.Open(nil, b[24:], &nonce, &cfg.EncryptionKey)
	if !ok {
		return nil, fmt.Errorf("invalid key")
	}

	inst := &Instance{}
	copy(inst.Nonce[:], b[0:24])
	inst.Seed = binary.BigEndian.Uint64(a[0:8])
	inst.Expiry = time.Unix(int64(binary.BigEndian.Uint64(a[8:16])), 0)
	codeLen := a[16]
	inst.Code = string(a[17 : 17+codeLen])
	inst.key = key

	return inst, nil
}

// Given a key-string, tries to decode it into an instance.
//
// Returns an error if the key is invalid.
func (cfg *Config) DecodeInstance(key string) (*Instance, error) {
	inst, err := cfg.decodeInstance(key)

	if err != nil {
		exDecodeFailures.Add(1)
	} else {
		exDecodeSuccesses.Add(1)
	}

	return inst, err
}

// Determines whether a code satisfies the Instance. If the code is valid, the
// instance key is registered in the spent instance pool.
func (cfg *Config) verify(instance *Instance, input string) bool {
	input = strings.ToUpper(input)
	input = spRepl.Replace(input)

	if len(input) != len(instance.Code) {
		return false
	}

	if numMismatches(instance.Code, input) > cfg.Leeway {
		return false
	}

	if cfg.checkSpentInstance(instance) {
		// already used
		return false
	}

	cfg.registerSpentInstance(instance)

	return true
}

// Verify whether an input is valid for an instance. Returns true iff the input
// is considered correct.
func (cfg *Config) Verify(instance *Instance, input string) bool {
	ok := cfg.verify(instance, input)

	if ok {
		exVerifySuccesses.Add(1)
	} else {
		exVerifyFailures.Add(1)
	}

	return ok
}

func (cfg *Config) checkSpentInstance(instance *Instance) bool {
	if cfg.CheckSpentInstance != nil {
		return cfg.CheckSpentInstance(instance)
	}

	k := cfg.Key(instance)

	// Finds the lowest index with expiry >= the instance expiry.
	x := sort.Search(len(cfg.spentKeyHeap), func(i int) bool {
		return cfg.spentKeyHeap[i].expiry.After(instance.Expiry) ||
			cfg.spentKeyHeap[i].expiry.Equal(instance.Expiry)
	})

	if x == len(cfg.spentKeyHeap) {
		return false
	}

	// The values of an instance are never changed so the expiry is
	// guaranteed to match. So we can stop searching if we go beyond
	// the expected expiry.
	for cfg.spentKeyHeap[x].expiry.Equal(instance.Expiry) {
		if cfg.spentKeyHeap[x].key == k {
			return true
		}
		x++
	}

	cfg.cleanHeap()

	return false
}

func (cfg *Config) cleanHeap() {
	if len(cfg.spentKeyHeap) < 1 {
		return
	}

	now := time.Now()
	oldLen := len(cfg.spentKeyHeap)

	for cfg.spentKeyHeap[0].expiry.Before(now) {
		heap.Pop(&cfg.spentKeyHeap)
	}

	newLen := len(cfg.spentKeyHeap)
	exSpentHeapInstanceCount.Add(int64(newLen - oldLen))
}

func (cfg *Config) registerSpentInstance(instance *Instance) error {
	if cfg.RegisterSpentInstance != nil {
		return cfg.RegisterSpentInstance(instance)
	}

	oldLen := len(cfg.spentKeyHeap)

	heap.Push(&cfg.spentKeyHeap, spentKey{
		key:    cfg.Key(instance),
		expiry: instance.Expiry,
	})

	newLen := len(cfg.spentKeyHeap)
	exSpentHeapInstanceCount.Add(int64(newLen - oldLen))

	return nil
}

type handler struct {
	cfg    *Config
	prefix string
}

// Returns an http.Handler for the given URL prefix.
//
// The Handler must be mapped using http.Handle using exactly the prefix
// specified.  The prefix should end in a slash (e.g. "/captcha/").
func (cfg *Config) Handler(prefix string) http.Handler {
	return &handler{cfg: cfg, prefix: prefix}
}

// http://.../some/handler/ASLSADASLDAJLDWLKLKASDLSJLASKDASKLDSL
// http://.../some/handler/ASLSADASLDAJLDWLKLKASDLSJLASKDASKLDSL.gif
// http://.../some/handler/extra/ASLSADASLDAJLDWLKLKASDLSJLASKDASKLDSL
func (h *handler) stripPrefix(url *url.URL) (string, error) {
	if p := strings.TrimPrefix(url.Path, h.prefix); len(p) < len(url.Path) {
		return p, nil
	}

	return "", errWrongPrefix
}

var re_validURL = regexp.MustCompilePOSIX(`^([a-zA-Z0-9_-]+=*)(\.[a-zA-Z]{3})?$`)

func (h *handler) determineKeyFromURL(path string) (string, error) {
	// We now have "<base64>" or "<base64>.<ext>"
	// or "<extra>/<base64>" or "<extra>/<base64>.<ext>".
	// The latter forms are invalid.
	ka := re_validURL.FindStringSubmatch(path)
	if len(ka) < 2 {
		return "", errInvalidURL
	}

	return ka[1], nil
}

var errWrongPrefix = fmt.Errorf("wrong prefix")
var errInvalidURL = fmt.Errorf("invalid URL")

func (h *handler) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	path, err := h.stripPrefix(req.URL)
	if err != nil {
		http.NotFound(rw, req)
		return
	}

	if !h.cfg.DisallowHandlerNew && path == "new" {
		instance := h.cfg.NewInstance()
		k := h.cfg.Key(&instance)

		rw.Header().Set("Content-Type", "text/plain")
		io.WriteString(rw, k)

		exNewInstancesServed.Add(1)
		return
	}

	k, err := h.determineKeyFromURL(path)
	if err != nil {
		http.NotFound(rw, req)
		return
	}

	instance, err := h.cfg.DecodeInstance(k)
	if err != nil {
		http.NotFound(rw, req)
		return
	}

	img, err := h.cfg.Image(instance)
	if err != nil {
		http.Error(rw, "Internal Server Error", 500)
		return
	}

	rw.Header().Set("Content-Type", imageMIME)
	encodeImage(img, rw)
}

// Length must already have been checked.
func numMismatches(a, b string) int {
	n := 0
	for i := range a {
		if a[i] != b[i] {
			n++
		}
	}
	return n
}

var ctbl = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"

func rstr(n int, r *rand.Rand) string {
	s := ""
	for i := 0; i < n; i++ {
		idx := r.Intn(len(ctbl))
		s += string(ctbl[idx])
	}
	return s
}

// Taken from code.google.com/p/3dcaptcha/TextGen.php.
var markovTransitionMatrix = []float64{
	0.0001, 0.0218, 0.0528, 0.1184, 0.1189, 0.1277, 0.1450, 0.1458, 0.1914,
	0.1915, 0.2028, 0.2792, 0.3131, 0.5293, 0.5304, 0.5448, 0.5448, 0.6397,
	0.7581, 0.9047, 0.9185, 0.9502, 0.9600, 0.9601, 0.9982, 1.0000, 0.0893,
	0.0950, 0.0950, 0.0950, 0.4471, 0.4471, 0.4471, 0.4471, 0.4784, 0.4821,
	0.4821, 0.6075, 0.6078, 0.6078, 0.7300, 0.7300, 0.7300, 0.7979, 0.8220,
	0.8296, 0.9342, 0.9348, 0.9351, 0.9351, 1.0000, 1.0000, 0.1313, 0.1317,
	0.1433, 0.1433, 0.3264, 0.3264, 0.3264, 0.4887, 0.5454, 0.5454, 0.5946,
	0.6255, 0.6255, 0.6255, 0.8022, 0.8022, 0.8035, 0.8720, 0.8753, 0.9545,
	0.9928, 0.9928, 0.9928, 0.9928, 1.0000, 1.0000, 0.0542, 0.0587, 0.0590,
	0.0840, 0.3725, 0.3837, 0.3879, 0.3887, 0.5203, 0.5208, 0.5211, 0.5390,
	0.5435, 0.5550, 0.8183, 0.8191, 0.8191, 0.8759, 0.9376, 0.9400, 0.9629,
	0.9648, 0.9664, 0.9664, 1.0000, 1.0000, 0.0860, 0.0877, 0.1111, 0.2533,
	0.3017, 0.3125, 0.3183, 0.3211, 0.3350, 0.3355, 0.3378, 0.4042, 0.4381,
	0.5655, 0.5727, 0.5842, 0.5852, 0.7817, 0.8718, 0.9191, 0.9201, 0.9530,
	0.9652, 0.9792, 0.9998, 1.0000, 0.1033, 0.1037, 0.1050, 0.1057, 0.2916,
	0.3321, 0.3324, 0.3324, 0.4337, 0.4337, 0.4337, 0.4912, 0.4912, 0.4912,
	0.7237, 0.7274, 0.7274, 0.8545, 0.8569, 0.9150, 0.9986, 0.9986, 0.9990,
	0.9990, 1.0000, 1.0000, 0.1014, 0.1017, 0.1024, 0.1028, 0.2725, 0.2729,
	0.2855, 0.4981, 0.5770, 0.5770, 0.5770, 0.6184, 0.6191, 0.6384, 0.7783,
	0.7797, 0.7797, 0.9249, 0.9663, 0.9688, 0.9923, 0.9923, 0.9937, 0.9937,
	1.0000, 1.0000, 0.2577, 0.2579, 0.2580, 0.2581, 0.6967, 0.6970, 0.6970,
	0.6970, 0.8648, 0.8648, 0.8650, 0.8661, 0.8667, 0.8670, 0.9397, 0.9397,
	0.9397, 0.9509, 0.9533, 0.9855, 0.9926, 0.9926, 0.9929, 0.9929, 1.0000,
	1.0000, 0.0324, 0.0478, 0.0870, 0.1267, 0.1585, 0.1908, 0.2182, 0.2183,
	0.2193, 0.2193, 0.2309, 0.2859, 0.3426, 0.6110, 0.6501, 0.6579, 0.6583,
	0.6923, 0.8211, 0.9764, 0.9781, 0.9948, 0.9949, 0.9965, 0.9965, 1.0000,
	0.1276, 0.1276, 0.1276, 0.1276, 0.4286, 0.4286, 0.4286, 0.4286, 0.4337,
	0.4337, 0.4337, 0.4337, 0.4337, 0.4337, 0.6684, 0.6684, 0.6684, 0.6684,
	0.6684, 0.6684, 1.0000, 1.0000, 1.0000, 1.0000, 1.0000, 1.0000, 0.0033,
	0.0059, 0.0100, 0.0109, 0.5401, 0.5443, 0.5477, 0.5485, 0.7149, 0.7149,
	0.7149, 0.7316, 0.7333, 0.9247, 0.9264, 0.9273, 0.9273, 0.9289, 0.9791,
	0.9816, 0.9824, 0.9824, 0.9833, 0.9833, 1.0000, 1.0000, 0.0850, 0.0865,
	0.0874, 0.1753, 0.3439, 0.3725, 0.3744, 0.3746, 0.5083, 0.5083, 0.5192,
	0.6784, 0.6840, 0.6848, 0.8088, 0.8128, 0.8128, 0.8147, 0.8326, 0.8511,
	0.8743, 0.8817, 0.9054, 0.9054, 1.0000, 1.0000, 0.1562, 0.1760, 0.1774,
	0.1776, 0.5513, 0.5517, 0.5517, 0.5520, 0.6352, 0.6352, 0.6352, 0.6369,
	0.6486, 0.6499, 0.7717, 0.8230, 0.8230, 0.8337, 0.8697, 0.8703, 0.9376,
	0.9376, 0.9378, 0.9378, 1.0000, 1.0000, 0.0255, 0.0265, 0.0682, 0.2986,
	0.4139, 0.4204, 0.6002, 0.6009, 0.6351, 0.6360, 0.6507, 0.6672, 0.6679,
	0.6786, 0.7718, 0.7723, 0.7732, 0.7873, 0.8364, 0.9715, 0.9753, 0.9797,
	0.9803, 0.9804, 0.9997, 1.0000, 0.0050, 0.0089, 0.0183, 0.0379, 0.0410,
	0.1451, 0.1494, 0.1514, 0.1654, 0.1656, 0.1866, 0.2171, 0.2821, 0.4272,
	0.4761, 0.4926, 0.4927, 0.6434, 0.6722, 0.7195, 0.9126, 0.9332, 0.9913,
	0.9925, 0.9999, 1.0000, 0.1596, 0.1688, 0.1688, 0.1688, 0.3799, 0.3799,
	0.3799, 0.4011, 0.4827, 0.4827, 0.4833, 0.6081, 0.6087, 0.6090, 0.7353,
	0.7953, 0.7953, 0.8804, 0.9181, 0.9584, 0.9952, 0.9952, 0.9952, 0.9952,
	1.0000, 1.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000,
	0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000,
	0.0000, 0.0000, 0.0000, 0.0000, 1.0000, 1.0000, 1.0000, 1.0000, 1.0000,
	1.0000, 0.0902, 0.0938, 0.1003, 0.1555, 0.4505, 0.4606, 0.4705, 0.4740,
	0.5928, 0.5928, 0.6018, 0.6201, 0.6402, 0.6605, 0.7619, 0.7666, 0.7671,
	0.8125, 0.8645, 0.9029, 0.9226, 0.9298, 0.9319, 0.9319, 0.9996, 1.0000,
	0.0584, 0.0598, 0.0903, 0.0912, 0.2850, 0.2870, 0.2883, 0.3902, 0.5057,
	0.5058, 0.5165, 0.5271, 0.5400, 0.5447, 0.6525, 0.6762, 0.6792, 0.6792,
	0.7512, 0.9370, 0.9843, 0.9851, 0.9953, 0.9953, 0.9999, 1.0000, 0.0416,
	0.0419, 0.0466, 0.0467, 0.1673, 0.1696, 0.1697, 0.6314, 0.7003, 0.7003,
	0.7003, 0.7142, 0.7150, 0.7160, 0.8626, 0.8626, 0.8627, 0.9023, 0.9255,
	0.9498, 0.9746, 0.9746, 0.9812, 0.9812, 0.9998, 1.0000, 0.0141, 0.0308,
	0.0668, 0.0877, 0.1241, 0.1282, 0.1874, 0.1874, 0.2191, 0.2192, 0.2210,
	0.3626, 0.3794, 0.4618, 0.4632, 0.5097, 0.5097, 0.6957, 0.8373, 0.9949,
	0.9949, 0.9961, 0.9963, 0.9982, 0.9984, 1.0000, 0.0740, 0.0740, 0.0740,
	0.0740, 0.8423, 0.8423, 0.8423, 0.8423, 0.9486, 0.9486, 0.9486, 0.9486,
	0.9486, 0.9491, 0.9836, 0.9836, 0.9836, 0.9849, 0.9849, 0.9849, 0.9907,
	0.9907, 0.9907, 0.9907, 1.0000, 1.0000, 0.2785, 0.2789, 0.2795, 0.2823,
	0.4088, 0.4118, 0.4118, 0.6070, 0.7774, 0.7774, 0.7782, 0.7840, 0.7840,
	0.8334, 0.9704, 0.9704, 0.9704, 0.9861, 0.9996, 1.0000, 1.0000, 1.0000,
	1.0000, 1.0000, 1.0000, 1.0000, 0.0741, 0.0741, 0.1963, 0.1963, 0.2519,
	0.2741, 0.2741, 0.3333, 0.4000, 0.4000, 0.4000, 0.4000, 0.4000, 0.4000,
	0.4037, 0.6741, 0.7667, 0.7667, 0.7667, 0.9667, 0.9963, 0.9963, 0.9963,
	0.9963, 1.0000, 1.0000, 0.0082, 0.0130, 0.0208, 0.0225, 0.1587, 0.1608,
	0.1613, 0.1686, 0.2028, 0.2028, 0.2032, 0.2322, 0.2391, 0.2417, 0.8232,
	0.8314, 0.8314, 0.8409, 0.9529, 0.9965, 0.9965, 0.9965, 0.9991, 0.9996,
	1.0000, 1.0000, 0.0678, 0.0678, 0.0763, 0.0763, 0.7373, 0.7373, 0.7373,
	0.7458, 0.8729, 0.8729, 0.8729, 0.8814, 0.8814, 0.8814, 0.9237, 0.9237,
	0.9237, 0.9237, 0.9237, 0.9407, 0.9492, 0.9492, 0.9492, 0.9492, 0.9492,
	1.0000,
}

// Taken from code.google.com/p/3dcaptcha/TextGen.php.
func rstrMarkov(n int, r *rand.Rand) string {
	s := ""
	c := r.Intn(26)
	for i := 0; i < n; i++ {
		s += string(c + 65)
		next := r.Float64()
		for j := 0; j < 26; j++ {
			if next < markovTransitionMatrix[c*26+j] {
				c = j
				break
			}
		}
	}
	return s
}

func spaceCode(s string, r *rand.Rand) string {
	ss := ""
	for i := range s {
		ss += string(s[i])
		if r.Intn(2) > 0 {
			ss += " "
		}
	}
	return ss
}

// Returns an image deterministically generated from the Generator parameters
// and the Instance.
func (cfg *Config) Image(instance *Instance) (image.Image, error) {
	if len(cfg.fonts) == 0 {
		panic("must set font directory first")
	}

	pNoiseSeed := instance.Seed //int64(52)

	rsrc := rand.NewSource(int64(pNoiseSeed))
	rand := rand.New(rsrc)

	pRot := -0.05 + rand.Float64()*0.02

	pStr := spaceCode(instance.Code, rand) //"4BOSPX93"

	w := cfg.Width
	h := cfg.Height

	crand := func(l, h int) int {
		return l + rand.Intn(h-l)
	}

	pX := crand(w/4, 3*w/4)
	pY := crand(h/4, 3*h/4)
	margin := 10

	r := image.NewRGBA(image.Rect(-margin, -margin, w+margin, h+margin))

	// Set up the random noise background.
	for y := -margin; y < h+margin; y++ {
		for x := -margin; x < w+margin; x++ {
			c := 255 - uint8(rand.Intn(192))
			r.SetRGBA(x, y, color.RGBA{c, c, c, 255})
			//r.SetRGBA(x,y,color.RGBA{255-uint8(rand.Intn(192)),255-uint8(rand.Intn(192)),255-uint8(rand.Intn(192)),255})
		}
	}

	// Choose a random font.
	fdata := cfg.fonts[rand.Intn(len(cfg.fonts))]
	f := draw2d.GetFont(fdata)
	if f == nil {
		panic("no font")
	}

	ctx := draw2dimg.NewGraphicContext(r)

	// Draw some random thick lines across the image from top to bottom.
	for i := 0; i < 4; i++ {
		ctx.MoveTo(float64(rand.Intn(w)), -10)
		ctx.LineTo(float64(w)-float64(rand.Intn(w)), float64(h+10))
		ctx.SetLineWidth(float64(crand(10-3, 10+3)))
		ctx.SetLineCap(draw2d.ButtCap)
		ctx.SetStrokeColor(color.RGBA{0, 0, 0, uint8(100 + rand.Intn(30))})
		ctx.Stroke()
	}

	ctx.SetFontData(fdata)
	ctx.SetFontSize(float64(20 + rand.Intn(4)))
	ctx.SetLineWidth(1)
	ctx.SetFillColor(color.RGBA{0, 0, 0, uint8(250 + rand.Intn(1))})

	ctx.Save()

	// Add the actual code string with random rotation and scale.
	ctx.Rotate(pRot * 3.1419 * 0)
	ctx.Scale(0.4, 1) //1.8*(rand.Float64()+0.5))
	//ctx.SetFillColor(color.RGBA{255,255,255,255})
	ctx.FillStringAt(pStr, float64(pX), float64(pY))

	// Add some additional random strings with lower opacity
	// to add background noise.
	for i := 0; i < 4; i++ {
		ctx.Restore()
		ctx.Rotate(0.04 * rand.Float64() * 3.1419)
		ctx.Scale(1.0, 1.0)
		ctx.SetFillColor(color.RGBA{0, 0, 0, uint8(70 + rand.Intn(10))})
		ctx.FillStringAt(rstr(8, rand), float64(rand.Intn(w/2)), float64(rand.Intn(h)))
	}

	// Create a new image for XORing additional shapes onto the image.
	r2 := image.NewRGBA(image.Rect(-margin, -margin, w+margin, h+margin))
	ctx2 := draw2dimg.NewGraphicContext(r2)

	// The second image starts all black.
	for y := 0; y < h; y++ {
		for x := 0; x < w; x++ {
			r2.SetRGBA(x, y, color.RGBA{0, 0, 0, 255})
		}
	}

	// Place several white filled circles on the second image.
	for i := 0; i < 4; i++ {
		dim := crand(18-2, 18+2)
		ctx2.ArcTo(float64(crand(pX-30, pX+30)), float64(crand(pY-30, pY+30)),
			float64(dim), float64(dim), 0, math.Pi*2)
		ctx2.SetFillColor(color.RGBA{255, 255, 255, 255})
		ctx2.Fill()
	}

	// Merge the first image with the second image, inverting the pixels
	// of the first image when the second image's corresponding pixel
	// is non-black. The resulting effect is that several circles on the
	// image appear to invert the colours of the pixels underneath.
	for y := -margin; y < h+margin; y++ {
		for x := -margin; x < w+margin; x++ {
			c := r.At(x, y).(color.RGBA)
			c2 := r2.At(x, y).(color.RGBA)
			c3 := color.RGBA{c.R, c.G, c.B, 255}
			if c2.R > 10 {
				c3.R = 255 - c3.R // ^c3.R
			}
			if c2.G > 10 {
				c3.G = 255 - c3.G //^c3.G
			}
			if c2.B > 10 {
				c3.B = 255 - c3.B //^c3.B
			}
			c3.A = 255
			r2.SetRGBA(x, y, c3)
		}
	}

	// distort from dchest/captcha
	amplitude := float64(crand(5, 10))
	period := float64(crand(100, 200))

	r3 := image.NewRGBA(image.Rect(0, 0, w, h))
	dx := 2.0 * math.Pi / period
	for x := 0; x < w; x++ {
		for y := 0; y < h; y++ {
			xo := amplitude * math.Sin(float64(y)*dx)
			yo := amplitude * math.Cos(float64(x)*dx)
			r3.SetRGBA(x, y, r2.RGBAAt(x+int(xo), y+int(yo)))
		}
	}

	exImagesGenerated.Add(1)

	return r3, nil
}

func encodeImage(img image.Image, w io.Writer) error {
	return gif.Encode(w, img, &gif.Options{
		NumColors: 256,
	})
}

// You can use this to convert an image to a base64 data: URL string.
//
// You can use this if serving images from an HTTP handler is inconvenient for
// your application.
func ImageToDataURL(img image.Image) (string, error) {
	b := bytes.Buffer{}

	_, err := b.WriteString("data:" + imageMIME + ";base64,")
	if err != nil {
		return "", err
	}

	e := base64.NewEncoder(base64.StdEncoding, &b)
	err = encodeImage(img, e)
	if err != nil {
		return "", err
	}

	return b.String(), nil
}
