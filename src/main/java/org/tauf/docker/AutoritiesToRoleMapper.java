package org.tauf.docker;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.stereotype.Component;

@Component
public class AutoritiesToRoleMapper {


    public AutoritiesToRoleMapper() {


    }

    public String getUserRole(String domain, Authentication authentication) {
        for (GrantedAuthority authority : authentication.getAuthorities()) {
            if ("ROLE_ADMINS".equals(authority.getAuthority())) {
                return "admin";
            }
        }
        return "guest";
    }
}
