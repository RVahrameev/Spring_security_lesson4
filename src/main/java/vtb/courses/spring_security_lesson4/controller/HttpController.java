package vtb.courses.spring_security_lesson4.controller;

import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;

@Controller
public class HttpController {
    @GetMapping("/")
    public String index(Model model) {
        model.addAttribute("name", SecurityContextHolder.getContext().getAuthentication().getName());
        return "index";
    }

    @GetMapping("/info")
    public String info(Model model) {
        model.addAttribute("name", SecurityContextHolder.getContext().getAuthentication().getName());
        model.addAttribute("auth_object", SecurityContextHolder.getContext().getAuthentication());
        return "info";
    }

}
