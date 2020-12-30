package com.jonesun.oauth2resourceserver.persistence.repository;

import com.jonesun.oauth2resourceserver.persistence.model.Foo;
import org.springframework.data.repository.PagingAndSortingRepository;

public interface IFooRepository extends PagingAndSortingRepository<Foo, Long> {
}
