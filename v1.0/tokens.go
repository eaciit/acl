package acl

import (
	"github.com/eaciit/orm/v1"
	"time"
)

type Token struct {
	orm.ModelBase `bson:"-",json:"-"`
	ID            string    `json:"_id",bson:"_id"`
	UserID        string    // `json:"UserId",bson:"UserId"`
	Created       time.Time // `json:"Created",bson:"Created"`
	Expired       time.Time // `json:"Expired",bson:"Expired"`
	Claimed       time.Time // `json:"Claimed",bson:"Claimed"`
	Purpose       string    // `json:"Purpose",bson:"Purpose"`
	Data1         string    // `json:"Data1",bson:"Data1"`
	Data2         string    // `json:"Data2",bson:"Data2"`
	Data3         string    // `json:"Data3",bson:"Data3"`
	Data4         string    // `json:"Data4",bson:"Data4"`
}

func (t *Token) TableName() string {
	return "acl_tokens"
}

func (t *Token) RecordID() interface{} {
	return t.ID
}

func (t *Token) Claim() {
	t.Claimed = time.Now()
	Save(t)
}
