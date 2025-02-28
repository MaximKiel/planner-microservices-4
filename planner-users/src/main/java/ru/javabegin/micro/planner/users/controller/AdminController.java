package ru.javabegin.micro.planner.users.controller;

import org.keycloak.admin.client.CreatedResponseUtil;
import org.keycloak.representations.idm.UserRepresentation;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import ru.javabegin.micro.planner.users.dto.UserDTO;
import ru.javabegin.micro.planner.users.keycloak.KeycloakUtils;
import ru.javabegin.micro.planner.users.mq.func.MessageFuncActions;
import ru.javabegin.micro.planner.utils.rest.webclient.UserWebClientBuilder;

import javax.ws.rs.core.Response;
import java.util.ArrayList;
import java.util.List;


/*

Чтобы дать меньше шансов для взлома (например, CSRF атак): POST/PUT запросы могут изменять/фильтровать закрытые данные, а GET запросы - для получения незащищенных данных
Т.е. GET-запросы не должны использоваться для изменения/получения секретных данных

Если возникнет exception - вернется код  500 Internal Server Error, поэтому не нужно все действия оборачивать в try-catch

Используем @RestController вместо обычного @Controller, чтобы все ответы сразу оборачивались в JSON,
иначе пришлось бы добавлять лишние объекты в код, использовать @ResponseBody для ответа, указывать тип отправки JSON

Названия методов могут быть любыми, главное не дублировать их имена и URL mapping

*/

@RestController
@RequestMapping("/admin/user") // базовый URI
public class AdminController {

    public static final String ID_COLUMN = "id"; // имя столбца id
    private static final int CONFLICT = 409; // если пользователь уже существует в KC и пытаемся создать такого же
    private static final String USER_ROLE_NAME = "user"; // название роли из KC
    private final KeycloakUtils keycloakUtils;

    // используем автоматическое внедрение экземпляра класса через конструктор
    // не используем @Autowired ля переменной класса, т.к. "Field injection is not recommended "
    public AdminController(KeycloakUtils keycloakUtils, MessageFuncActions messageFuncActions, UserWebClientBuilder userWebClientBuilder) {
        this.keycloakUtils = keycloakUtils;
    }

    // добавление
    @PostMapping("/add")
    public ResponseEntity add(@RequestBody UserDTO userDTO) {

        // если передали пустое значение
        if (userDTO.getEmail() == null || userDTO.getEmail().trim().length() == 0) {
            return new ResponseEntity("missed param: email", HttpStatus.NOT_ACCEPTABLE);
        }

        if (userDTO.getPassword() == null || userDTO.getPassword().trim().length() == 0) {
            return new ResponseEntity("missed param: password", HttpStatus.NOT_ACCEPTABLE);
        }

        if (userDTO.getUsername() == null || userDTO.getUsername().trim().length() == 0) {
            return new ResponseEntity("missed param: username", HttpStatus.NOT_ACCEPTABLE);
        }

        // создаем пользователя
        Response createdResponse = keycloakUtils.createKeycloakUser(userDTO);

        if (createdResponse.getStatus() == CONFLICT) {
            return new ResponseEntity("user or email already exists " + userDTO.getEmail(), HttpStatus.CONFLICT);
        }

        // получаем его ID
        String userId = CreatedResponseUtil.getCreatedId(createdResponse);

        System.out.printf("User created with userId: %s%n", userId);

        List<String> defaultRoles = new ArrayList<>();
        defaultRoles.add(USER_ROLE_NAME); // эта роль должна присутствовать в KC на уровне Realm
        defaultRoles.add("admin");

        keycloakUtils.addRoles(userId, defaultRoles);

        return ResponseEntity.status(createdResponse.getStatus()).build();
    }

    // обновление
    @PutMapping("/update")
    public ResponseEntity<UserDTO> update(@RequestBody UserDTO userDTO) {

        // проверка на обязательные параметры
        if (userDTO.getId().isBlank()) {
            return new ResponseEntity("missed param: id", HttpStatus.NOT_ACCEPTABLE);
        }

        // save работает как на добавление, так и на обновление
        keycloakUtils.updateKeycloakUser(userDTO);

        return new ResponseEntity(HttpStatus.OK); // просто отправляем статус 200 (операция прошла успешно)
    }

    // для удаления используем типа запроса put, а не delete, т.к. он позволяет передавать значение в body, а не в адресной строке
    @PostMapping("/deletebyid")
    public ResponseEntity deleteByUserId(@RequestBody String userId) {

        keycloakUtils.deleteKeycloakUser(userId);

        return new ResponseEntity(HttpStatus.OK);

    }

    // получение объекта по id
    @PostMapping("/id")
    public ResponseEntity<UserRepresentation> findById(@RequestBody String userId) {

        return ResponseEntity.ok(keycloakUtils.findUserById(userId));
    }

    // получение уникального объекта по email
    @PostMapping("/search")
    public ResponseEntity<List<UserRepresentation>> search(@RequestBody String email) { // строго соответствие email
        return ResponseEntity.ok(keycloakUtils.searchKeycloakUsers("email:" + email));
    }
}