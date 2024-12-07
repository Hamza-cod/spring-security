package com.auth.authentication.service.security;

import com.auth.authentication.repository.TokenRepository;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import java.security.Key;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;

@Service
public class JwtService {
    @Autowired
    private  TokenRepository tokenRepository;
    @Value("${application.security.jwt.secret-key}")
    private  String secretKey;

    @Value("${application.security.jwt.expiration}")
    private long jwtExpirationMilliSec;
    @Value("${application.security.jwt.refresh-expiration}")
    private long refreshExpirationMilliSec;


    public String extractUsername(String token){
        return extractClaim(token , Claims::getSubject);
    }
    public String generateToken(UserDetails userDetails){
        return generateToken(new HashMap<>(), userDetails);
    }
    public String generateToken(Map<String,Object> extraClaims,
                                UserDetails userDetails){
        return buildToken(extraClaims,userDetails,jwtExpirationMilliSec);
    }
    public String generateRefreshToken(UserDetails userDetails){
        return buildToken(new HashMap<>(), userDetails,refreshExpirationMilliSec);
    }

    private String buildToken(Map<String,Object> extraClaims,
                              UserDetails userDetails,long expiration){
        return Jwts.builder().claims(extraClaims).
                subject(userDetails.getUsername()).issuedAt(new Date(System.currentTimeMillis())).
                expiration(new Date(System.currentTimeMillis() + expiration))
                .signWith(getSignInKey(), SignatureAlgorithm.HS256).compact();

    }

    public boolean isTokenValid(String token , UserDetails  userDetails){
        var optionalToken = this.tokenRepository.findByToken(token);
        final String username = extractUsername(token);
        return (username.equals(userDetails.getUsername())) && !isTokeExpaired(token) && optionalToken.isPresent();
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
        byte[]  keyBytes = Decoders.BASE64.decode(secretKey);
        return Keys.hmacShaKeyFor(keyBytes);
    }
}
