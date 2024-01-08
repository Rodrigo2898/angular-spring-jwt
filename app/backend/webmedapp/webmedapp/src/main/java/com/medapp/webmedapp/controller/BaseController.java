package com.medapp.webmedapp.controller;

import com.medapp.webmedapp.dto.BaseDTO;
import com.medapp.webmedapp.entity.BaseEntity;
import com.medapp.webmedapp.service.BaseService;
import jakarta.validation.Valid;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.Optional;

public abstract class BaseController<ID, Entity extends BaseEntity<ID>, DTO extends BaseDTO<ID>,
        ShallowDTO extends BaseDTO<ID>> {

    @GetMapping
    public ResponseEntity<List<ShallowDTO>> list(DTO filter, Pageable pageable) {
        Page<ShallowDTO> entityPage = getService().listar(filter, pageable);

        return ResponseEntity
                .ok()
                .header("X-Total-Count", Long.toString(entityPage.getTotalElements()))
                .body(entityPage.getContent());
    }

    @GetMapping("/{id}")
    public ResponseEntity<DTO> find(@PathVariable ID id) {
        Optional<DTO> optionalDTO = getService().buscar(id);

        if (optionalDTO.isEmpty()) {
            return ResponseEntity.notFound().build();
        }
        return ResponseEntity.ok(optionalDTO.get());
    }

    @PostMapping
    public ResponseEntity<DTO> save(@Valid @RequestBody DTO dto) {
        return ResponseEntity.ok(getService().salvar(dto));
    }

    @PutMapping("/{id}")
    public ResponseEntity<DTO> update(@Valid @PathVariable ID id, @RequestBody DTO dto) {
        if (getService().buscar(id).isEmpty())
            return ResponseEntity.notFound().build();
        dto.setId(id);
        return ResponseEntity.ok(getService().salvar(dto));
    }

    @DeleteMapping("/{id}")
    public ResponseEntity<?> delete(@PathVariable ID id) {
        getService().excluir(id);
        return ResponseEntity.noContent().build();
    }

    protected abstract BaseService<ID, Entity, DTO, ShallowDTO> getService();
}
