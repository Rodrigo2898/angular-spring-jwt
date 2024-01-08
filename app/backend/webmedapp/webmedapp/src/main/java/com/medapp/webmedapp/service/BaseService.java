package com.medapp.webmedapp.service;

import com.medapp.webmedapp.dto.BaseDTO;
import com.medapp.webmedapp.entity.BaseEntity;
import com.medapp.webmedapp.mapper.BaseMapper;
import com.medapp.webmedapp.repository.BaseRepository;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.transaction.annotation.Transactional;

import java.util.Objects;
import java.util.Optional;

@Transactional
public abstract class BaseService<ID, Entity extends BaseEntity<ID>, DTO extends BaseDTO<ID>, ShallowDTO extends BaseDTO<ID>> {

    protected final Log logger = LogFactory.getLog(getClass());

    public abstract Page<ShallowDTO> listar(DTO filter, Pageable pageable);

    public Optional<DTO> buscar(ID id) {
        Optional<Entity> optionalEntity = getRepository().findById(id);

        return optionalEntity.map(entity -> getEntityMapper().EntityToDTO(entity));
    }

    public DTO salvar(DTO dto) {
        Entity entity = getEntityMapper().DTOToEntity(dto);

        getRepository().save(entity);

        return getEntityMapper().EntityToDTO(entity);
    }

    public void excluir(ID id) {
        getRepository().findById(id).ifPresent((entity) -> {
            getRepository().deleteById(entity.getId());
        });
    }

    protected abstract BaseRepository<Entity, ID> getRepository();

    protected abstract BaseMapper<Entity, DTO, ShallowDTO> getEntityMapper();

    protected Pageable getPageableDefault(Pageable pageable) {
        if (Objects.isNull(pageable)) {
            return PageRequest.of(0, 20);
        }
        return pageable;
    }
}
