package vtb.courses.spring_security_lesson4.security;

import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Date;
import java.util.List;

/**
 * TokenRevocationCheckService - класс для хранения и проверки по списку отозванных JWT токенов
 * Асинхронно раз в час обновляет список по "файлу"
 */
@Component
public class TokenRevocationCheckService implements RevocationCheckService{
    long lastUpdated = 0;
    List<String> revocatedTokens;

    private void startUpdate() {
        new Thread(this::updateRevocatedTokens).start();
    }
    public void updateRevocatedTokens() {
        List<String> revocatedTokens = new ArrayList<>();
        // Тут по хорошему переделать на загрузку из файла
        revocatedTokens.add("eyJraWQiOiJksThhNWY2Mi1lY2U5LTRhYmEtYWFmMi1jMTkzMTUxMmE5YTYiLCJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJhbGljZSIsInNjcCI6IlJPTEVfVVNFUiwgUk9MRV9BRE1JTiIsImV4cCI6MTcyMjU4Njk3MSwianRpIjoiNTA3ZjAyOTktZWMyYS00MzhkLTljNzAtMDU1NzExZTEwNTliIn0.hblNV5M1VrDPiz0M45ZO3nc3IyKBLcRp6k-SkstT4CBLguTiqZNSwtjsO5dQh_MB-UXdnNaSxYlwXG8YF_5OYiCKxFB3Kq87TE1BLtq4w_ZzTUjLoB1PchNvYM9ubGmvfzaQ2NJEeQw0lheZ48nrnMXFo9DUmr4PUeUKPuefEy0xFaR_p7PNEWXhLUosqGU2cGo4FaUPEdy4qnXYF2k-cHhLoWCbI-PteHslENTYnXuyKcrOeQe79FlSOtsCnMFyNnF3ZezeQiS6EVOUOKBY9HO4W0vqDgOdNzBrpeddzp-s88LF3jEroEbF4FhsDAX-ACGuOxoHZeFbvsEkVxYM9g");
        revocatedTokens.add("eZJraWQiOiJksThhNWY2Mi1lY2U5LTRhYmEtYWFmMi1jMTkzMTUxMmE5YTYiLCJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJhbGljZSIsInNjcCI6IlJPTEVfVVNFUiwgUk9MRV9BRE1JTiIsImV4cCI6MTcyMjU4Njk3MSwianRpIjoiNTA3ZjAyOTktZWMyYS00MzhkLTljNzAtMDU1NzExZTEwNTliIn0.hblNV5M1VrDPiz0M45ZO3nc3IyKBLcRp6k-SkstT4CBLguTiqZNSwtjsO5dQh_MB-UXdnNaSxYlwXG8YF_5OYiCKxFB3Kq87TE1BLtq4w_ZzTUjLoB1PchNvYM9ubGmvfzaQ2NJEeQw0lheZ48nrnMXFo9DUmr4PUeUKPuefEy0xFaR_p7PNEWXhLUosqGU2cGo4FaUPEdy4qnXYF2k-cHhLoWCbI-PteHslENTYnXuyKcrOeQe79FlSOtsCnMFyNnF3ZezeQiS6EVOUOKBY9HO4W0vqDgOdNzBrpeddzp-s88LF3jEroEbF4FhsDAX-ACGuOxoHZeFbvsEkVxYM9g");
        // Подменяем список на новый
        synchronized (this) {
            this.revocatedTokens = revocatedTokens;
        }
        lastUpdated = new Date().getTime();
    }
    @Override
    public boolean IsRevocate(String token) {
        boolean res;
        synchronized (this) {
            res = Arrays.stream(revocatedTokens.toArray()).anyMatch(s -> s.equals(token));
        }
        // не чаще чем раз в час запускаем перечитку списка отозванных токенов
        if (new Date().getTime() - lastUpdated > 60 * 60 * 1000) {
            startUpdate();
        }
        return res;
    }

    public TokenRevocationCheckService() {
        startUpdate();
    }
}
