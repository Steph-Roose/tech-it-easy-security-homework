package nl.novi.techiteasy1121.services;


import nl.novi.techiteasy1121.dtos.UserDto;
import nl.novi.techiteasy1121.exceptions.BadRequestException;
import nl.novi.techiteasy1121.exceptions.UsernameNotFoundException;
import nl.novi.techiteasy1121.models.Authority;
import nl.novi.techiteasy1121.models.User;
import nl.novi.techiteasy1121.repositories.UserRepository;
import nl.novi.techiteasy1121.utils.RandomStringGenerator;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.Set;

@Service
public class UserService {

    private final UserRepository userRepo;

    @Autowired
    public UserService(UserRepository userRepo) {
        this.userRepo = userRepo;
    }

    public List<UserDto> getUsers() {
        List<UserDto> collection = new ArrayList<>();
        List<User> list = userRepo.findAll();
        for (User user : list) {
            collection.add(fromUser(user));
        }
        return collection;
    }

    public UserDto getUser(String username) {
        UserDto dto = new UserDto();
        Optional<User> user = userRepo.findById(username);
        if (user.isPresent()){
            dto = fromUser(user.get());
        }else {
            throw new UsernameNotFoundException(username);
        }
        return dto;
    }

    public boolean userExists(String username) {
        return userRepo.existsById(username);
    }

    public String createUser(UserDto userDto) {
        String randomString = RandomStringGenerator.generateAlphaNumeric(20);
        userDto.setApikey(randomString);
        User newUser = userRepo.save(toUser(userDto));
        return newUser.getUsername();
    }

    public void deleteUser(String username) {
        userRepo.deleteById(username);
    }

    public void updateUser(String username, UserDto newUser) {
        if (!userRepo.existsById(username)) throw new BadRequestException();
        User user = userRepo.findById(username).get();
        user.setPassword(newUser.getPassword());
        userRepo.save(user);
    }

    public Set<Authority> getAuthorities(String username) {
        if (!userRepo.existsById(username)) throw new UsernameNotFoundException(username);
        User user = userRepo.findById(username).get();
        UserDto userDto = fromUser(user);
        return userDto.getAuthorities();
    }

    public void addAuthority(String username, String authority) {

        if (!userRepo.existsById(username)) throw new UsernameNotFoundException(username);
        User user = userRepo.findById(username).get();
        user.addAuthority(new Authority(username, authority));
        userRepo.save(user);
    }

    public void removeAuthority(String username, String authority) {
        if (!userRepo.existsById(username)) throw new UsernameNotFoundException(username);
        User user = userRepo.findById(username).get();
        Authority authorityToRemove = user.getAuthorities().stream().filter((a) -> a.getAuthority().equalsIgnoreCase(authority)).findAny().get();
        user.removeAuthority(authorityToRemove);
        userRepo.save(user);
    }

    public static UserDto fromUser(User user){

        var dto = new UserDto();

        dto.username = user.getUsername();
        dto.password = user.getPassword();
        dto.enabled = user.isEnabled();
        dto.apikey = user.getApikey();
        dto.email = user.getEmail();
        dto.authorities = user.getAuthorities();

        return dto;
    }

    public User toUser(UserDto userDto) {

        var user = new User();

        user.setUsername(userDto.getUsername());
        user.setPassword(userDto.getPassword());
        user.setEnabled(userDto.getEnabled());
        user.setApikey(userDto.getApikey());
        user.setEmail(userDto.getEmail());

        return user;
    }

}
