package com.jonesun.oauth2resourceserver.service.impl;


import com.jonesun.oauth2resourceserver.persistence.model.Foo;
import com.jonesun.oauth2resourceserver.persistence.repository.IFooRepository;
import com.jonesun.oauth2resourceserver.service.IFooService;
import org.springframework.stereotype.Service;

import java.util.Optional;

@Service
public class FooServiceImpl implements IFooService {

    private IFooRepository fooRepository;

    public FooServiceImpl(IFooRepository fooRepository) {
        this.fooRepository = fooRepository;
    }

    @Override
    public Optional<Foo> findById(Long id) {
        return fooRepository.findById(id);
    }

    @Override
    public Foo save(Foo foo) {
        return fooRepository.save(foo);
    }

    @Override
    public Iterable<Foo> findAll() {
        return fooRepository.findAll();
    }
}
