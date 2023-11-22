package com.security.Spring.Security.manager;

import com.security.Spring.Security.manager.dto.request.ManagerLoginRequest;
import com.security.Spring.Security.manager.dto.response.ManagerLoginResponse;
import com.security.Spring.Security.manager.service.ManagerService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.parameters.RequestBody;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/manager")
@RequiredArgsConstructor
@Tag(name = "Management")
public class ManagerController {
    private final ManagerService managerService;


    @Operation(
            description = "Get endpoint for manager",
            summary = "This is a summary for management get endpoint",
            responses = {
                    @ApiResponse(
                            description = "Success",
                            responseCode = "200"
                    ),
                    @ApiResponse(
                            description = "Unauthorized / Invalid Token",
                            responseCode = "401"
                    )
            }

    )
    @GetMapping
    public String get() {
        return "GET:: management controller";
    }
    @PostMapping
    public String post() {
        return "POST:: management controller";
    }
    @PutMapping
    public String put() {
        return "PUT:: management controller";
    }
    @DeleteMapping
    public String delete() {
        return "DELETE:: management controller";
    }

    @PostMapping("login")
    public ResponseEntity<?>  managerLogin(@Valid @RequestBody ManagerLoginRequest loginRequest){
        ManagerLoginResponse managerLoginResponse = managerService.managerLogin(loginRequest);
        return ResponseEntity.ok(managerLoginResponse);
    }
}
