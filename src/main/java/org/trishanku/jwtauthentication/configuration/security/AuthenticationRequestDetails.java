package org.trishanku.jwtauthentication.configuration.security;

import lombok.*;

@AllArgsConstructor
@NoArgsConstructor
@Data
@Builder
public class AuthenticationRequestDetails {

    private String emailAddress;
    private String password;
}
