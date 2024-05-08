package juhe

import (
	gosms "github.com/pkg6/go-sms"
	"reflect"
	"testing"
)

func TestGateWay(t *testing.T) {
	type args struct {
		key string
	}
	tests := []struct {
		name string
		args args
		want gosms.IGateway
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := GateWay(tt.args.key); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("GateWay() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestJuHe_AsName(t *testing.T) {
	type fields struct {
		Key   string
		DType string
		Lock  gosms.Lock
	}
	tests := []struct {
		name   string
		fields fields
		want   string
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			g := JuHe{
				Key:   tt.fields.Key,
				DType: tt.fields.DType,
				Lock:  tt.fields.Lock,
			}
			if got := g.AsName(); got != tt.want {
				t.Errorf("AsName() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestJuHe_I(t *testing.T) {
	type fields struct {
		Key   string
		DType string
		Lock  gosms.Lock
	}
	tests := []struct {
		name   string
		fields fields
		want   gosms.IGateway
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			g := JuHe{
				Key:   tt.fields.Key,
				DType: tt.fields.DType,
				Lock:  tt.fields.Lock,
			}
			if got := g.I(); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("I() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestJuHe_Send(t *testing.T) {
	type fields struct {
		Key   string
		DType string
		Lock  gosms.Lock
	}
	type args struct {
		to      gosms.IPhoneNumber
		message gosms.IMessage
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		want    gosms.SMSResult
		wantErr bool
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			g := JuHe{
				Key:   tt.fields.Key,
				DType: tt.fields.DType,
				Lock:  tt.fields.Lock,
			}
			got, err := g.Send(tt.args.to, tt.args.message)
			if (err != nil) != tt.wantErr {
				t.Errorf("Send() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("Send() got = %v, want %v", got, tt.want)
			}
		})
	}
}
