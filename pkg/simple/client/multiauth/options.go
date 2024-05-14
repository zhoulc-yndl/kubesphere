package multiauth

type Options struct {
	FAOpenStatus bool   `json:"faOpenStatus"`
	FAType       string `json:"faType"`
	Issuer       string `json:"issuer"`
}

// NewOptions returns a default nil options
func NewOptions() *Options {
	return &Options{
		FAOpenStatus: false,
		FAType:       "",
		Issuer:       "cwift.shdata.com",
	}
}
