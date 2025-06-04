package main

import (
	"bufio"
	"crypto/hmac"
	"crypto/md5"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
)

// WebhookPayload представляет структуру данных, получаемую в вебхуке.
type WebhookPayload struct {
	TransactionID      int                    `json:"transaction_id"`
	Reference          string                 `json:"reference"`
	ApiKey             string                 `json:"api_key"`
	Amount             float64                `json:"amount"`
	Currency           string                 `json:"currency"`
	Status             int                    `json:"status"`
	StatusName         string                 `json:"status_name"`
	SystemAmount       float64                `json:"system_amount"`
	SystemCurrency     string                 `json:"system_currency"`
	OperationAmount    float64                `json:"operation_amount"`
	Commission         float64                `json:"commission"`
	PaymentSystemType  string                 `json:"payment_system_type"`
	CardNumber         *string                `json:"card_number,omitempty"`
	CardPan6           *string                `json:"card_pan6,omitempty"`
	CardPan4           *string                `json:"card_pan4,omitempty"`
	CardholderName     *string                `json:"cardholder_name,omitempty"`
	ProcessingErrorMsg *string                `json:"processing_error_msg,omitempty"`
	AuthorizationCode  *string                `json:"authorization_code,omitempty"`
	PayToken           *string                `json:"pay_token,omitempty"`
	Params             map[string]interface{} `json:"params,omitempty"`
	RefundInitType     *int                   `json:"refund_init_type,omitempty"`
}

// loadEnv загружает переменные окружения из файла .env
func loadEnv(filename string) error {
	file, err := os.Open(filename)
	if err != nil {
		return err
	}
	defer file.Close()
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		// Пропускаем пустые строки и комментарии
		if strings.TrimSpace(line) == "" || strings.HasPrefix(line, "#") {
			continue
		}
		// Разделяем ключ и значение
		parts := strings.SplitN(line, "=", 2)
		if len(parts) != 2 {
			continue
		}
		key := strings.TrimSpace(parts[0])
		value := strings.TrimSpace(parts[1])
		// Устанавливаем переменную окружения
		os.Setenv(key, value)
	}
	return scanner.Err()

}

// handleWebhook обрабатывает входящие POST-запросы на вебхук.
func handleWebhook(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Invalid request method", http.StatusMethodNotAllowed)
		return
	}

	// Читаем тело запроса
	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "Failed to read request body", http.StatusInternalServerError)
		return
	}
	defer r.Body.Close()
	var data struct {
		Data string `json:"data"`
		Sign string `json:"sign"`
	}
	err = json.Unmarshal(body, &data)
	// Декодируем данные из Base64
	fmt.Println(string(body))
	decodedData, err := base64.StdEncoding.DecodeString(data.Data)
	if err != nil {
		http.Error(w, "Failed to decode data", http.StatusBadRequest)
		return
	}

	if !VerifyResponseSignature([]byte(data.Data), data.Sign, os.Getenv("secret")) {
		http.Error(w, "Invalid signature", http.StatusUnauthorized)
		return
	}

	// Обрабатываем данные
	var payload WebhookPayload
	if err := json.Unmarshal(decodedData, &payload); err != nil {
		http.Error(w, "Failed to unmarshal JSON", http.StatusBadRequest)
		return
	}

	// Здесь вы можете обработать payload по своему усмотрению
	log.Printf("Received webhook: %+v\n", payload)

	// Возвращаем ответ "OK"
	w.Write([]byte("OK"))
}

// generateHMAC генерирует HMAC-подпись для данных с использованием заданного ключа.
func generateHMAC(data []byte, key string) string {
	h := hmac.New(md5.New, []byte(key))
	h.Write(data)
	return hex.EncodeToString(h.Sum(nil))
}

func main() {
	err := loadEnv(".env")
	fmt.Println(err)
	fmt.Println(os.Getenv("secret"))
	http.HandleFunc("/webhook", handleWebhook)
	log.Println("Starting server on :8080")
	if err := http.ListenAndServe(":8080", nil); err != nil {
		log.Fatal(err)
	}
}

func CalculateSignatureHashHmac(body []byte, secret string) string {
	mac := hmac.New(md5.New, []byte(secret))
	mac.Write(body)
	return fmt.Sprintf("%x", mac.Sum(nil))
}

func VerifyResponseSignature(data []byte, receivedSign, secret string) bool {
	h := hmac.New(md5.New, []byte(secret))
	h.Write(data)
	expectedSign := fmt.Sprintf("%x", h.Sum(nil))
	fmt.Println("signature verify", hmac.Equal([]byte(expectedSign), []byte(receivedSign)))
	return hmac.Equal([]byte(expectedSign), []byte(receivedSign))
}

func EncodeToString(data []byte) string {
	return base64.StdEncoding.EncodeToString(data)
}

func DecodeString(encodedData string) ([]byte, error) {
	return base64.StdEncoding.DecodeString(encodedData)
}
