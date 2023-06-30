package main

import (
	"context"
	"fmt"
	"github.com/Entetry/authService/internal/config"
	"github.com/Entetry/authService/internal/handler"
	"github.com/Entetry/authService/internal/repository"
	"github.com/Entetry/authService/internal/service"
	"github.com/Entetry/authService/protocol/authService"
	"github.com/Entetry/userService/protocol/userService"
	log "github.com/sirupsen/logrus"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
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
	log.Info(cfg.UserEndpoint)

	userConn, err := grpc.Dial(cfg.UserEndpoint,
		grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		log.Panicf("Couldn't connect to user service: %v", err)
	}
	userServiceClient := userService.NewUserServiceClient(userConn)
	defer func() {
		err = userConn.Close()
		if err != nil {
			log.Errorf("Main / userConn.Close() / \n %v", err)
			return
		}
	}()

	sessionStorage := repository.NewRefreshSessionStorage(&sync.Map{})
	authSvc := service.NewAuthService(jwtCfg, sessionStorage, userServiceClient)
	authHandler := handler.NewAuth(authSvc)
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
