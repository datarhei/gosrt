package srt

// RequestAttributes Allows passing data from connection handler to publish and subscribe handlers
type RequestAttributes interface {
	// Get Returns value stored using the given key, returns true if found otherwise false
	Get(key string) (any, bool)

	// GetValue returns the value stored using the given key. If the value does not exist then nil is returned.
	// Unlike the `Get` function, this function does not return any indication that the returned nil is the actual
	// retrieved value or not.
	GetValue(key string) any

	// Set Sets attribute
	Set(key string, value any)

	// Has Checks if attribute set contains given key
	Has(key string) bool
}

type connRequestAttributes struct {
	attrs map[string]any
}

func (c *connRequestAttributes) Get(key string) (any, bool) {
	v, ok := c.attrs[key]
	return v, ok
}

func (c *connRequestAttributes) GetValue(key string) any {
	return c.attrs[key]
}

func (c *connRequestAttributes) Set(key string, value any) {
	c.attrs[key] = value
}

func (c *connRequestAttributes) Has(key string) bool {
	_, ok := c.attrs[key]
	return ok
}

type AttributeContainer interface {
	GetRequestAttributes() RequestAttributes
}

func GetRequestAttributes(t any) RequestAttributes {
	if ra, ok := t.(AttributeContainer); ok {
		return ra.GetRequestAttributes()
	}
	return nil
}
