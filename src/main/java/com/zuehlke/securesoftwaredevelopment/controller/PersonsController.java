package com.zuehlke.securesoftwaredevelopment.controller;

import com.zuehlke.securesoftwaredevelopment.config.AuditLogger;
import com.zuehlke.securesoftwaredevelopment.config.SecurityUtil;
import com.zuehlke.securesoftwaredevelopment.domain.Person;
import com.zuehlke.securesoftwaredevelopment.domain.Role;
import com.zuehlke.securesoftwaredevelopment.domain.User;
import com.zuehlke.securesoftwaredevelopment.repository.PersonRepository;
import com.zuehlke.securesoftwaredevelopment.repository.RoleRepository;
import com.zuehlke.securesoftwaredevelopment.repository.UserRepository;
import com.zuehlke.securesoftwaredevelopment.service.PermissionService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.parameters.P;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;

import javax.servlet.http.HttpSession;
import java.sql.SQLException;
import java.util.List;
import java.util.stream.Collectors;

@Controller

public class PersonsController {

    private static final Logger LOG = LoggerFactory.getLogger(PersonsController.class);
    private static final AuditLogger auditLogger = AuditLogger.getAuditLogger(PersonRepository.class);

    private final PersonRepository personRepository;
    private final UserRepository userRepository;
    private final PermissionService permissionService;

    public PersonsController(PersonRepository personRepository, UserRepository userRepository, PermissionService permissionService) {
        this.personRepository = personRepository;
        this.userRepository = userRepository;
        this.permissionService = permissionService;
    }

    @GetMapping("/persons/{id}")
    @PreAuthorize("hasAuthority('VIEW_PERSON')")
    public String person(@PathVariable int id, Model model, HttpSession session) {
        model.addAttribute("person", personRepository.get("" + id));
        String csrfToken = session.getAttribute("CSRF_TOKEN").toString();
        System.out.println(csrfToken);
        model.addAttribute("csrf_token", csrfToken);
        return "person";
    }

    @GetMapping("/myprofile")
    @PreAuthorize("hasAuthority('VIEW_MY_PROFILE')")
    public String self(Model model, Authentication authentication) {
        User user = (User) authentication.getPrincipal();
        model.addAttribute("person", personRepository.get("" + user.getId()));
        return "person";
    }

    @DeleteMapping("/persons/{id}")
    // ovu permisiju nemaju kupac i menadzer
    @PreAuthorize("hasAuthority('UPDATE_PERSON')")
    public ResponseEntity<Void> person(@PathVariable int id) {

        User user = SecurityUtil.getCurrentUser();
        List<String> userRoles = permissionService.getRoles(user.getId()).stream().map(Role::getName).collect(Collectors.toList());
        if(userRoles.contains("BUYER") || userRoles.contains("MANAGER")){
            if(user.getId() != id) throw new AccessDeniedException("Forbidden");
        }

        personRepository.delete(id);
        userRepository.delete(id);

        return ResponseEntity.noContent().build();
    }

    @PostMapping("/update-person")
    @PreAuthorize("hasAuthority('UPDATE_PERSON')")
    public String updatePerson(Person person, @RequestParam("csrf_token") String csrfToken, HttpSession session) throws AccessDeniedException {

        User user = SecurityUtil.getCurrentUser();
        List<String> userRoles = permissionService.getRoles(user.getId()).stream().map(Role::getName).collect(Collectors.toList());
        if(userRoles.contains("BUYER") || userRoles.contains("MANAGER")){
            if(user.getId() != Integer.parseInt(person.getId())) throw new AccessDeniedException("Forbidden");
        }

        if(!session.getAttribute("CSRF_TOKEN").toString().equals(csrfToken)){
            throw new AccessDeniedException("Forbidden");
        }
        personRepository.update(person);
        return "redirect:/persons/" + person.getId();
    }

    @GetMapping("/persons")
    @PreAuthorize("hasAuthority('VIEW_PERSONS_LIST')")
    public String persons(Model model) {
        model.addAttribute("persons", personRepository.getAll());
        return "persons";
    }

    @GetMapping(value = "/persons/search", produces = "application/json")
    @ResponseBody
    public List<Person> searchPersons(@RequestParam String searchTerm) {
        LOG.info("Search term: " + searchTerm);
        return personRepository.search(searchTerm);
    }
}
