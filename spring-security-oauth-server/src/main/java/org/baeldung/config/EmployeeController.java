package org.baeldung.config;

import java.util.ArrayList;
import java.util.List;

import org.springframework.http.HttpStatus;
import org.baeldung.model.Employee;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.ResponseStatus;

@Controller
public class EmployeeController {

    private List<Employee> employees = new ArrayList<>();

    @RequestMapping(value = "/employee")
    @ResponseBody
    public Employee getEmployee(@RequestParam String email) {
        Employee result = employees.stream().filter(x -> email.equals(x.getEmail())).findAny().orElse(null);
        return result;
    }

    @RequestMapping(value = "/employee", method = RequestMethod.POST, consumes = MediaType.APPLICATION_JSON_VALUE)
    @ResponseStatus(HttpStatus.CREATED)
    public void postMessage(@RequestBody Employee employee) {
        employees.add(employee);
    }

}
