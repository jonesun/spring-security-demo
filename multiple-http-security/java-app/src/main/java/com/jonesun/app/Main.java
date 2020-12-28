package com.jonesun.app;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutionException;

/**
 * @author jone.sun
 * @date 2020-12-28 16:42
 */
public class Main {

    public static void main(String[] args) throws ExecutionException, InterruptedException, JsonProcessingException {
        ObjectMapper objectMapper = new ObjectMapper();
        LoginUser loginUser = new LoginUser();
        loginUser.setUsername("admin");
        loginUser.setPassword("123456");
        String requestBody = objectMapper
                .writerWithDefaultPrettyPrinter()
                .writeValueAsString(loginUser);

        HttpRequest request = HttpRequest.newBuilder(URI.create("http://localhost:8080/multiple-http-security-server/app/login"))
                .header("Content-Type", "application/json")
                .POST(HttpRequest.BodyPublishers.ofString(requestBody))
                .build();

        CompletableFuture<String> result = HttpClient.newHttpClient()
                .sendAsync(request, HttpResponse.BodyHandlers.ofString())
                .thenApply(HttpResponse::body)
                .thenApply(body -> {
                    try {
                        return objectMapper.readValue(body, LoginResponseResult.class);
                    } catch (IOException e) {
                        return new LoginResponseResult();
                    }
                })
                .thenCompose(loginResponseResult ->
                        HttpClient.newHttpClient().sendAsync(HttpRequest.newBuilder()
                                .uri(URI.create("http://localhost:8080/multiple-http-security-server/app/api/sayHello"))
                                .header("Authorization", "Bearer " + loginResponseResult.getToken())
                                .build(), HttpResponse.BodyHandlers.ofString())
                                .thenApply(HttpResponse::body));
        System.out.println(result.get());

    }

}
