package services

import (
	"crypto/ecdsa"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"github.com/gin-gonic/gin"
	"io"
	"net/http"
	"regexp"
	"sima-golang/config"
	"sima-golang/dtos"
	"sima-golang/utils"
	"strings"
	"time"
)

type ISimaService interface {
	GetData(context *gin.Context) (interface{}, error)  //tsQuery, tsCert, tsSignAlg, tsSign string)
	Callback(context *gin.Context) (interface{}, error) //tsCert, tsSignAlg, tsSign string
	GetAppURI() (interface{}, error)
	GetQrURI() (string, error)
}

type simaService struct {
}

func NewSimaService() ISimaService {
	return &simaService{}
}
func (s simaService) GetData(context *gin.Context) (interface{}, error) {

	// Request convert to byte array
	combineQueryString := getRequestPathAndQueryStringAsBytes(context.Request)
	// Request validation
	valid, err := tsCertValidation(context.GetHeader("ts-cert"), context.GetHeader("ts-sign"), combineQueryString)
	if err != nil || !valid {
		return &dtos.GetDataErrorResponseDto{ErrorMessage: "This request has not been addressed by the Sima application"}, fmt.Errorf("Invalid Certificate")
	}
	// tsQuery convert to Sima Contract object
	contract, err := tsQueryConvertToContract(context.Query("tsquery"))
	if err != nil {
		return &dtos.GetDataErrorResponseDto{ErrorMessage: "This request has not been addressed by the Sima application"}, fmt.Errorf("Invalid Query")
	}
	// For Auth
	if contract.SignableContainer.OperationInfo.Type == "Auth" {
		return &dtos.GetDataResponseDto{FileName: config.AUTH_FILENAME, Data: generateUUIDAsBase64ForAuth()}, nil
	}

	// Actions to be taken in accordance with the contact object

	// For Sign
	return &dtos.GetDataResponseDto{FileName: config.DUMMY_FILENAME, Data: config.DUMMY_FILE_BASE64}, nil

}

func (s simaService) Callback(context *gin.Context) (interface{}, error) {

	// Request body convert To byte Array
	bodyByteArr, err := getRequestBodyAsByteArr(context.Request)
	if err != nil {
		return &dtos.CallbackResponseDto{Status: "failed"}, fmt.Errorf("Invalid Request Body")
	}
	// Request Validation
	valid, err := tsCertValidation(context.GetHeader("ts-cert"), context.GetHeader("ts-sign"), bodyByteArr)
	if err != nil || !valid {
		return &dtos.CallbackResponseDto{Status: "failed"}, fmt.Errorf("This request has not been addressed by the Sima application")
	}

	// Request Body
	var body dtos.CallbackRequestDto
	err = json.Unmarshal(bodyByteArr, &body)
	if err != nil {
		return &dtos.CallbackResponseDto{Status: "failed"}, fmt.Errorf("Invalid Request Body")
	}

	// Sign Document User Information
	personalData, err := certToPersonalData(context.GetHeader("ts-cert"))
	if err != nil {
		return &dtos.CallbackResponseDto{Status: "failed"}, fmt.Errorf("Invalid Certificate")
	}
	fmt.Println(personalData)

	return &dtos.CallbackResponseDto{Status: "success"}, nil

}

func (s simaService) GetAppURI() (interface{}, error) {
	operationId := "10000000000000000000000000001"
	operationType := "Auth" // or "Sign"
	contract := createContract(operationId, operationType)
	signature, err := createSignature(contract.SignableContainer, "yourSecretKey")
	if err != nil {
		return nil, fmt.Errorf("Error creating signature:", err.Error())
	}
	contract.Header.Signature = signature
	encodedContract, err := encodeContract(contract)
	if err != nil {
		return nil, fmt.Errorf("Error encoding contract:", err.Error())
	}

	return fmt.Sprintf("%s%s", config.APP_URI_PREFIX, encodedContract), nil
}

func (s simaService) GetQrURI() (string, error) {
	operationId := "10000000000000000000000000001"
	operationType := "Sign" // or "Auth"
	contract := createContract(operationId, operationType)
	signature, err := createSignature(contract.SignableContainer, "yourSecretKey")
	if err != nil {
		return "", fmt.Errorf("Error creating signature:", err.Error())
	}
	contract.Header.Signature = signature
	encodedContract, err := encodeContract(contract)
	if err != nil {
		return "nil", fmt.Errorf("Error encoding contract:", err.Error())
	}

	return fmt.Sprintf("%s%s", config.QR_URI_PREFIX, encodedContract), nil
}

func getRequestPathAndQueryStringAsBytes(r *http.Request) []byte {
	requestPath := r.URL.Path
	queryString := r.URL.RawQuery
	requestPathAndQuery := strings.Join([]string{requestPath, queryString}, "?")
	return []byte(requestPathAndQuery)
}

func tsCertValidation(tsCert, tcSign string, processBuffer []byte) (bool, error) {
	// Parse the base64-encoded certificate
	certBytes, err := base64.StdEncoding.DecodeString(tsCert)
	if err != nil {
		return false, fmt.Errorf("failed to decode certificate: %v", err)
	}

	// Parse the X.509 certificate
	cert, err := x509.ParseCertificate(certBytes)
	if err != nil {
		return false, fmt.Errorf("failed to parse certificate: %v", err)
	}

	// Create an ECDSA public key from the parsed certificate's public key
	pubKey, ok := cert.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		return false, fmt.Errorf("certificate's public key is not of type ECDSA")
	}

	// Decode the base64-encoded signature
	signature, err := base64.StdEncoding.DecodeString(tcSign)
	if err != nil {
		return false, fmt.Errorf("failed to decode signature: %v", err)
	}

	// Verify the signature using the ECDSA public key
	hash := sha256.Sum256(processBuffer)
	valid := ecdsa.VerifyASN1(pubKey, hash[:], signature)

	return valid, nil
}

func tsQueryConvertToContract(tsQuery string) (*dtos.Contract, error) {
	byteArray, err := base64.StdEncoding.DecodeString(tsQuery)
	if err != nil {
		return nil, fmt.Errorf("failed to decode tsQuery: %v", err)
	}

	jsonStr := string(byteArray)
	contract := &dtos.Contract{}
	err = json.Unmarshal([]byte(jsonStr), contract)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal json: %v", err)
	}
	return contract, nil
}

func generateUUIDAsBase64ForAuth() string {
	uuid := utils.GenerateRandomUUID()
	byteBuffer := make([]byte, 16)
	binary.BigEndian.PutUint64(byteBuffer[:8], uuid.MostSignificantBits)
	binary.BigEndian.PutUint64(byteBuffer[8:], uuid.LeastSignificantBits)
	return base64.StdEncoding.EncodeToString(byteBuffer)
}

func getRequestBodyAsByteArr(request *http.Request) ([]byte, error) {
	body, err := io.ReadAll(request.Body)
	if err != nil {
		return []byte{}, err
	}
	defer request.Body.Close()

	return body, nil //string(body)
}

func certToPersonalData(cert string) (*dtos.SimaPersonalData, error) {
	certBytes, err := base64.StdEncoding.DecodeString(cert)
	if err != nil {
		return nil, err
	}

	certificate, err := x509.ParseCertificate(certBytes)
	if err != nil {
		return nil, err
	}

	subject := certificate.Subject.String()

	return &dtos.SimaPersonalData{
		Fin:      extractValueFromSubject(subject, "SERIALNUMBER"),
		Name:     extractValueFromSubject(subject, "GIVENNAME"), //
		Surname:  extractValueFromSubject(subject, "SURNAME"),   //
		FullName: extractValueFromSubject(subject, "CN"),
		Country:  extractValueFromSubject(subject, "C"),
	}, nil
}

func extractValueFromSubject(input, fieldName string) string {
	regex := fieldName + "=([^,]+)"
	pattern := regexp.MustCompile(regex)
	matches := pattern.FindStringSubmatch(input)

	if len(matches) > 1 {
		return strings.TrimSpace(matches[1])
	} else {
		switch fieldName {
		case "GIVENNAME":
			for key, value := range config.StaticData.OID_ACCORDING_TO_DN {
				if key == "GN" {
					newRegex := value + "=([^,]+)"
					newPattern := regexp.MustCompile(newRegex)
					matches = newPattern.FindStringSubmatch(input)
					if len(matches) > 1 {
						hexStringResult := strings.TrimSpace(matches[1])
						hexByte, err := hex.DecodeString(hexStringResult[1:])
						if err != nil {
							return "N/A"
						}
						return string(hexByte)[2:]
					}
				}
			}
		case "SURNAME":
			for key, value := range config.StaticData.OID_ACCORDING_TO_DN {
				if key == "SN" {
					newRegex := value + "=([^,]+)"
					newPattern := regexp.MustCompile(newRegex)
					matches = newPattern.FindStringSubmatch(input)
					if len(matches) > 1 {
						hexStringResult := strings.TrimSpace(matches[1])
						hexByte, err := hex.DecodeString(hexStringResult[1:])
						if err != nil {
							return "N/A"
						}
						return string(hexByte)[2:]
					}
				}
			}
		default:
			return "N/A"
		}
	}
	return "N/A"
}

func createContract(operationId string, operationType string) dtos.Contract {
	return dtos.Contract{
		Header: dtos.Header{
			AlgorithmName: "HmacSHA256",
		},
		SignableContainer: dtos.SignableContainer{
			ProtoInfo: dtos.ProtoInfo{
				Name:    "web2app",
				Version: "1.3",
			},
			OperationInfo: dtos.OperationInfo{
				OperationId: operationId,
				Type:        operationType,
				NbfUTC:      time.Now().Unix(),
				ExpUTC:      time.Now().Unix() + (200 * 60),
				Assignee:    []string{},
			},
			ClientInfo: dtos.ClientInfo{
				ClientId:    1,
				ClientName:  "ScanMe APP",
				IconURI:     "Icon Pulic URL",
				Callback:    "callbackURL",
				RedirectURI: "redirectionURL",
				HostName:    []string{},
			},
			DataInfo: dtos.DataInfo{},
		},
	}
}

func encodeContract(model dtos.Contract) (string, error) {
	jsonData, err := json.Marshal(model)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(jsonData), nil
}

func createSignature(model dtos.SignableContainer, secretKey string) ([]byte, error) {
	jsonData, err := json.Marshal(model)
	if err != nil {
		return nil, err
	}

	computedHashAsByte := computeSha256HashAsByte(jsonData)
	hMac := getHMAC(computedHashAsByte, []byte(secretKey))
	return hMac, nil
}

func computeSha256HashAsByte(input []byte) []byte {
	hash := sha256.New()
	hash.Write(input)
	return hash.Sum(nil)
}

func getHMAC(data, key []byte) []byte {
	hash := hmac.New(sha256.New, key)
	hash.Write(data)
	return hash.Sum(nil)
}
