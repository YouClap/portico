package main

import (
	firebase "firebase.google.com/go"
	"firebase.google.com/go/auth"
	"golang.org/x/net/context"
	"google.golang.org/api/option"
)

func initializeAdminSDK(ctx context.Context) (*firebase.App, error) {
	opt := option.WithCredentialsFile("firebase-admin.json")

	return firebase.NewApp(ctx, nil, opt)
}

func initializeAuthClient(ctx context.Context, firebaseApp *firebase.App) (*auth.Client, error) {
	return firebaseApp.Auth(ctx)
}
