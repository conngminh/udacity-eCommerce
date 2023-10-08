package com.example.demo.model.security;

import com.example.demo.model.persistence.repositories.UserRepository;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import static java.util.Collections.emptyList;

@Service
public class UserDetailsServiceImplementor implements UserDetailsService {
    private final UserRepository applicationUserRepository;

    public UserDetailsServiceImplementor(UserRepository applicationUserRepository) {
        this.applicationUserRepository = applicationUserRepository;
    }

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        // Retrieve the user from the repository by username
        com.example.demo.model.persistence.User applicationUser = applicationUserRepository.findByUsername(username);
        // If the user is not found, throw an exception
        if (applicationUser == null) {
            throw new UsernameNotFoundException("User not found with username: " + username);
        }
        // Create and return a UserDetails object with the user's information
        return new org.springframework.security.core.userdetails.User(
                applicationUser.getUsername(),
                applicationUser.getPassword(),
                emptyList()
        );
    }
}