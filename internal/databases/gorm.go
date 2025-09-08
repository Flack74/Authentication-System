package databases

import (
	"fmt"

	"github.com/Flack74/go-auth-system/internal/config"
	"github.com/Flack74/go-auth-system/internal/models"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

func NewGormDB(cfg *config.Config) (*gorm.DB, error) {
	dsn := fmt.Sprintf("host=%s port=%s user=%s password=%s dbname=%s sslmode=%s",
		cfg.DBHost, cfg.DBPort, cfg.DBUser, cfg.DBPassword, cfg.DBName, cfg.DBSSLMode)

	db, err := gorm.Open(postgres.Open(dsn), &gorm.Config{})
	if err != nil {
		return nil, err
	}

	// Auto-migrate the schema
	err = db.AutoMigrate(&models.GormUser{})
	if err != nil {
		return nil, err
	}

	return db, nil
}