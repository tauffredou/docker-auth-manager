package org.tauf.docker.domain;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.util.Base64Utils;

import javax.persistence.Entity;
import javax.persistence.Id;
import java.io.IOException;
import java.util.Date;
import java.util.UUID;

@Entity
public class Token {
    @Id
    @JsonIgnore
    private String id;
    private String username;
    private String role;
    @JsonIgnore
    private Date expiration;

    static ObjectMapper mapper = new ObjectMapper();

    public Token() {
    }

    public Token(String username, String role, Date expiration) {
        this.id = UUID.randomUUID().toString();
        this.username = username;
        this.role = role;
        this.expiration = expiration;
    }

    public String getId() {
        return id;
    }

    public void setId(String id) {
        this.id = id;
    }

    public String getUsername() {
        return username;
    }

    public void setUsername(String username) {
        this.username = username;
    }

    public Date getExpiration() {
        return expiration;
    }

    public void setExpiration(Date expiration) {
        this.expiration = expiration;
    }

    public String getRole() {
        return role;
    }

    public void setRole(String role) {
        this.role = role;
    }

    public String encode() throws JsonProcessingException {
//        String json = mapper.writeValueAsString(this);
        String json = String.format("{\"username\":\"%s\",\"role\":\"%s\"}", username, role);
        System.out.println(json);
        return Base64Utils.encodeToUrlSafeString(json.getBytes()).replace("=","");
    }

    public static Token decode(String tokenBase64) throws IOException {

        Token token = mapper.readValue(Base64Utils.decodeFromUrlSafeString(tokenBase64), Token.class);
        return token;
    }
}
