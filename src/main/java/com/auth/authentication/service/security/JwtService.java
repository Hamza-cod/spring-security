package com.auth.authentication.service.security;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import java.security.Key;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;

@Service
public class JwtService {
    private static final String SECRET_KEY = "d41d5747c85936ec34ceb5617fa68828e089dcb79e784d62a0851cc5a34f159bde0ec3ddcab3e5b4dd544aa7d583fa3998102168ae542055360c238db3988efedefeb2907b140f1308a5d5c6076c2ea5f0cb6210a24634645ab7b397f2921b0b429010b91d6ab864a4e7f93379d52e9e4bba8fd1076385492c60808370e179814b85bff455cc9b5dfb62e1a706d675048c24aefa54a06f61d1e63a87e7f298bad98b3dded04d94c65bb0c6c8228757061824ccf440b5ebaa6bfbb1d27d2e1982f3dc07549654973c9bf95bc7eebbf3237b5f924e4b1f3f79";

    public String extractUsername(String token){
        return extractClaim(token , Claims::getSubject);
    }
    public String generateToken(UserDetails userDetails){
        return generateToken(new HashMap<>(), userDetails);
    }
    public String generateToken(Map<String,Object> extraClaims,
                                UserDetails userDetails){
        return Jwts.builder().claims(extraClaims).
                subject(userDetails.getUsername()).issuedAt(new Date(System.currentTimeMillis())).
        expiration(new Date(System.currentTimeMillis() + 86400000))
                .signWith(getSignInKey(), SignatureAlgorithm.HS256).compact();
    }

    public boolean isTokenValid(String token , UserDetails  userDetails){
        final String username = extractUsername(token);
        return (username.equals(userDetails.getUsername())) && !isTokeExpaired(token);
    }

    private boolean isTokeExpaired(String token) {
        return extractExpiration(token).before(new Date());
    }

    private Date extractExpiration(String token) {
        return extractClaim(token,Claims::getExpiration);
    }

    public  <T> T extractClaim(String token, Function<Claims , T> claimsResolver){
        final Claims claims = extractAllClaims(token);
        return claimsResolver.apply(claims);
    }
    private Claims extractAllClaims(String token){
        return Jwts.
                parser().
                setSigningKey(getSignInKey())
                .build().parseClaimsJws(token).getBody();
    }
    private Key getSignInKey(){
        byte[]  keyBytes = Decoders.BASE64.decode(SECRET_KEY);
        return Keys.hmacShaKeyFor(keyBytes);
    }
}
