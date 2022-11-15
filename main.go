package main

import (
	"bytes"
	"crypto/md5"
	"crypto/sha256"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"
)

type User struct {
	login   string
	passw   string
	ip_addr string
}

/*
 Если требуется POST - в строке 97 указать запрос на отправку.
 Если GET - изменить адрес в строке 98
 В строке 98 адрес.
*/

var user User = User{
	"<Пользователь>",
	"<Пароль>",
	"<Адрес>:<Порт>",
}

var client = &http.Client{}

func auth(url string) (bool, string) {
	request := posting("auth", "nil", "nil")
	response, err := client.Do(request)
	if err != nil {
		log.Println("Не удалось отправить запрос. Строка 30.", err)
	}
	cookieSet := strings.Split(response.Header["Set-Cookie"][0], ";")[0]
	if response.StatusCode == 401 {
		md5sum := user.login + ":" + response.Header["X-Ndm-Realm"][0] + ":" + user.passw // Хэш md5.
		sha := response.Header["X-Ndm-Challenge"][0] + fmt.Sprintf("%x", md5.Sum([]byte(md5sum)))
		password := sha256.Sum256([]byte(sha))                                                   // Хэш sha256.
		jsonStringAuth := fmt.Sprintf(`{"login": "%s", "password": "%x"}`, user.login, password) // Формируем json с логином и паролем.
		request = posting("auth", jsonStringAuth, cookieSet)
		response, err = client.Do(SetHeaders(request, cookieSet))
		if err != nil {
			log.Println("Не удалось отправить запрос. Строка 41.", err)
		}
		if response.StatusCode == 200 {
			return true, cookieSet
		}
	} else if response.StatusCode == 200 {
		return true, cookieSet
	}
	return false, ""
}

func posting(query string, post string, cookieSet string) *http.Request {
	url := "https://" + user.ip_addr + "/" + query

	if post != "nil" {
		request, err := http.NewRequest("POST", url, bytes.NewBuffer([]byte(post)))
		if err != nil {
			log.Println("Не удалось отправить запрос. Строка 55.", err)
		}

		return request
	} else {
		request, err := http.NewRequest("GET", url, nil)
		if err != nil {
			log.Println("Не удалось отправить запрос. Строка 62.", err)
		}
		return request
	}
}

func SetHeaders(request *http.Request, cookieSet string) *http.Request {
	/*
		Устанавливаем заголовки и куки.
	*/
	request.Header.Set("Cookie", cookieSet)
	request.Header.Set("Accept", "application/json, text/plain, */*")
	request.Header.Set("Content-Type", "application/json;charset=utf-8")
	request.Header.Set("Host", user.ip_addr)
	request.Header.Set("Referer", user.ip_addr+"/dashboard")
	request.Header.Set("Connection", "keep-alive")
	request.Header.Set("Accept-Encoding", "gzip, deflate")
	return request
}

func main() {
	url := "https://" + user.ip_addr + "/"
	accept, cookieSet := auth(url)
	if accept && cookieSet != "nil" {
		post := `nil`                                                    // Указывает Json в виде строки для POST. `nil` - Если нужен GET.
		request := posting("rci/ip/traffic-shape/host", post, cookieSet) // Адрес для отправки.
		response, err := client.Do(SetHeaders(request, cookieSet))
		if err != nil {
			log.Println("Не удалось отправить запрос. Строка 92.", err)
		}
		bodyText, err := io.ReadAll(response.Body) // Читаем ответ от сервера.
		if err != nil {
			log.Println("Не прочитать ответ от сервера. Строка 92.", err)
		}
		fmt.Println(string(bodyText))
	}
}
