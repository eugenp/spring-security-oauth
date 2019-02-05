package com.baeldung.resourceserverauth0.dao;

import org.springframework.data.repository.CrudRepository;

import com.baeldung.resourceserverauth0.model.Color;

public interface ColorRepository extends CrudRepository<Color, Long> {

}
