package com.jonesun.oauth2resourceserver.service;

import com.jonesun.oauth2resourceserver.persistence.model.Foo;

import java.util.Optional;


public interface IFooService {
    Optional<Foo> findById(Long id);

    Foo save(Foo foo);
    
    Iterable<Foo> findAll();

}
