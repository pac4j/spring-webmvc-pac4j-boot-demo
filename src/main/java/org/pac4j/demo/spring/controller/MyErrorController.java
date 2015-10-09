package org.pac4j.demo.spring.controller;

import org.springframework.boot.autoconfigure.web.BasicErrorController;
import org.springframework.boot.autoconfigure.web.DefaultErrorAttributes;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.servlet.ModelAndView;

import javax.servlet.http.HttpServletRequest;

@Controller
public class MyErrorController extends BasicErrorController {

    public MyErrorController() {
        super(new DefaultErrorAttributes());
    }

    @RequestMapping(
            value = {"${error.path:/error}"},
            produces = {"text/html"}
    )
    public ModelAndView errorHtml(HttpServletRequest request) {
        final HttpStatus status = getStatus(request);
        if (status == HttpStatus.UNAUTHORIZED) {
            return new ModelAndView("error401");
        } else if (status == HttpStatus.FORBIDDEN) {
            return new ModelAndView("error403");
        } else {
            return new ModelAndView("error500");
        }
    }

    private HttpStatus getStatus(HttpServletRequest request) {
        Integer statusCode = (Integer)request.getAttribute("javax.servlet.error.status_code");
        if(statusCode != null) {
            try {
                return HttpStatus.valueOf(statusCode.intValue());
            } catch (Exception e) {
            }
        }
        return HttpStatus.INTERNAL_SERVER_ERROR;
    }
}
