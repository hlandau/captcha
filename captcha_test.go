package captcha

import "testing"

func TestKeySerialization(t *testing.T) {
	cfg := Config{}

	for i := 0; i < 5; i++ {
		instance := cfg.NewInstance()
		k := cfg.Key(&instance)
		instance2, err := cfg.DecodeInstance(k)
		if err != nil {
			t.Fatalf("failed to decode instance: %v", err)
		}

		k2 := cfg.Key(instance2)

		if k != k2 {
			t.Errorf("Instance keys do not match: %s != %s", k, k2)
		}
	}
}
