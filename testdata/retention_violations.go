package testdata

import (
	"net/http"
	"time"
)

// Simulated Redis client for AST pattern matching.
type fakeRedisClient struct{}

func (r *fakeRedisClient) Set(ctx interface{}, key string, value interface{}, ttl time.Duration) {}
func (r *fakeRedisClient) SetNX(ctx interface{}, key string, value interface{}, ttl time.Duration) {
}
func (r *fakeRedisClient) HSet(ctx interface{}, key string, values ...interface{}) {}
func (r *fakeRedisClient) Expire(ctx interface{}, key string, ttl time.Duration)  {}

type fakeDB struct{}

func (d *fakeDB) Exec(query string, args ...interface{}) {}
func (d *fakeDB) Create(value interface{})                {}
func (d *fakeDB) Save(value interface{})                  {}

// PaymentRecord holds payment data for persistence tests.
type PaymentRecord struct {
	PAN string
	CVV string
}

var rdb = &fakeRedisClient{}
var db = &fakeDB{}

// StoreCardDataNoTTL stores card data in Redis without TTL.
// VIOLATION: RET-REDIS-NO-TTL - Redis Set with TTL=0 on sensitive data (3.2.1)
func StoreCardDataNoTTL(w http.ResponseWriter, r *http.Request) {
	cardData := "4111111111111111"
	rdb.Set(nil, "card_data", cardData, 0)
}

// StorePaymentHashNoExpire stores payment data in Redis HSet without Expire.
// VIOLATION: RET-REDIS-NO-EXPIRE - Redis HSet without Expire on sensitive data (3.2.1)
func StorePaymentHashNoExpire(w http.ResponseWriter, r *http.Request) {
	rdb.HSet(nil, "payment_hash", "pan", "4111111111111111")
}

// InsertCardToDB stores card data in SQL without expiry.
// VIOLATION: RET-DB-SENSITIVE-STORE - Sensitive data in persistent DB (3.2.1)
func InsertCardToDB(w http.ResponseWriter, r *http.Request) {
	cardNumber := "4111111111111111"
	db.Exec("INSERT INTO cards (number) VALUES (?)", cardNumber)
}

// SavePaymentRecordGorm stores payment record via gorm.
// VIOLATION: RET-GORM-SENSITIVE-STORE - Sensitive data in persistent ORM storage (3.2.1)
func SavePaymentRecordGorm(w http.ResponseWriter, r *http.Request) {
	record := &PaymentRecord{PAN: "4111", CVV: "123"}
	db.Create(record)
}

func authorize(data []byte) {}
func clearData(data []byte) {}

// ProcessPaymentDeferZero uses defer for zeroing -- timing issue.
// VIOLATION: RET-ZERO-DEFER-ONLY - defer zeroing executes after response (3.2.1)
func ProcessPaymentDeferZero(w http.ResponseWriter, r *http.Request) {
	cardData := []byte("4111111111111111")
	defer clearData(cardData)
	authorize(cardData)
	w.Write([]byte("ok"))
}
