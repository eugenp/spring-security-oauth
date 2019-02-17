package com.baeldung.resourceserverauth0.web.controllers;

import java.util.ArrayList;
import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;

import com.baeldung.resourceserverauth0.dao.ColorRepository;
import com.baeldung.resourceserverauth0.model.Color;

@CrossOrigin(origins = "http://localhost:8080", allowedHeaders = "Authorization")
@RestController
@RequestMapping("/colors")
public class ColorsRestController {

    @Autowired
    ColorRepository repository;

    @GetMapping
    public List<Color> retrieveNonSecuredResource() {
        List<Color> colors = new ArrayList<>();
        repository.findAll()
            .forEach(colors::add);
        return colors;
    }

    @PostMapping
    @ResponseStatus(code = HttpStatus.CREATED)
    public void retrieveSecuredResource(@RequestBody String color) {
        repository.save(new Color(color));
    }

    @DeleteMapping("/{id}")
    public void retrieveNonAccessibledResource(@PathVariable("id") Long id) {
        repository.deleteById(id);
    }

}
