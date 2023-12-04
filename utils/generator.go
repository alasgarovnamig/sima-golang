package utils

import (
	"bytes"
	"fmt"
	"github.com/boombuler/barcode"
	"github.com/boombuler/barcode/qr"
	"image/png"
	"os"

	//"github.com/boombuler/barcode"
	//"github.com/boombuler/barcode/qr"
	"github.com/skip2/go-qrcode"

	"math/rand"
	//"os"
	"time"
)

type UUID struct {
	MostSignificantBits  uint64
	LeastSignificantBits uint64
}

func GenerateRandomUUID() UUID {
	return UUID{
		MostSignificantBits:  rand.Uint64(),
		LeastSignificantBits: rand.Uint64(),
	}
}

func GenerateQRCode(text string, width int, height int) ([]byte, error) {

	// Create a qr code with the given parameters

	qrCode, err := qr.Encode(text, qr.M, qr.Auto)

	if err != nil {

		return nil, err

	}

	// Resize the qr code to the desired width and height

	qrCode, err = barcode.Scale(qrCode, width, height)

	if err != nil {

		return nil, err

	}

	// Convert the qr code to a png image

	var buf bytes.Buffer

	err = png.Encode(&buf, qrCode)

	if err != nil {

		return nil, err

	}

	return buf.Bytes(), nil

}
func GenerateFileNameAccordingToLocalDateTime() string {
	now := time.Now()
	return fmt.Sprintf("sima_qr_%s.png", now.Format("20060102_150405000"))
}

func GenerateQrImage(data, filePath string, width, height int) error {
	// Generate QR code
	//qrCode, err := qrcode.New(data, qrcode.High)
	//if err != nil {
	//	return err
	//}
	qrCode, err := qrcode.New(data, qrcode.Medium)
	if err != nil {
		return err
	}
	//qrCode.DisableBorder = true // Disable the border if necessary
	//qrCode.Image(512)
	//// Save QR code to a file
	file, err := os.Create(filePath)
	if err != nil {
		return err
	}
	defer file.Close()

	// Encode the QR code to the file
	err = png.Encode(file, qrCode.Image(width))
	if err != nil {
		return err
	}

	return nil
}
