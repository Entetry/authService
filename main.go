package main

import (
	"authService/internal/config"
	"authService/internal/handler"
	"authService/internal/repository"
	"authService/internal/service"
	"authService/protocol/authService"
	"context"
	"fmt"
	log "github.com/sirupsen/logrus"
	"google.golang.org/grpc"
	"net"
	"os"
	"os/signal"
	"sync"
	"syscall"
)

func main() {
	cfg, err := config.New()
	if err != nil {
		log.Fatal(err)
	}
	jwtCfg, err := config.NewJwtConfig()
	if err != nil {
		log.Fatal(err)
	}
	_, cancel := context.WithCancel(context.Background())
	defer cancel()
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGTERM)
	sessionStorage := repository.NewRefreshSessionStorage(&sync.Map{})
	tokenService := service.NewAuthService(jwtCfg, sessionStorage)
	authHandler := handler.NewAuth(tokenService)
	grpcServer := grpc.NewServer()
	authService.RegisterAuthGRPCServiceServer(grpcServer, authHandler)
	go func() {
		<-sigChan
		cancel()
		grpcServer.GracefulStop()
		if err != nil {
			log.Errorf("can't stop server gracefully %v", err)
		}
	}()
	log.Info("grpc Server started on ", cfg.Port)
	listener, err := net.Listen("tcp", fmt.Sprintf(":%d", cfg.Port))
	if err != nil {
		log.Fatal(err)
	}
	if err := grpcServer.Serve(listener); err != nil {
		log.Fatalf("failed to serve: %v", err)
	}
}
