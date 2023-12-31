# jwt-graphql-server

Это простой GraphQL-сервер, который включает в себя механизмы аутентификации и авторизации с использованием JSON Web Tokens (JWT). Сервер предоставляет следующие функции:

- Регистрация новых пользователей.
- Вход в систему с проверкой учетных данных.
- Генерация и валидация JWT-токенов.
- Защита определенных GraphQL-запросов от неавторизованных пользователей.

## Установка

Для запуска проекта выполните следующие шаги:

```bash
npm install
npm start
```

Сервер будет доступен по адресу 'http://localhost:8001/graphql'

## Использование

### Регистрация нового пользователя

Отправьте POST-запрос с JSON-телом запроса:

```
mutation { 
  register(
    email: 'user@example.com', 
    password: 'password'
  ) { 
    access_token 
  } 
}
```

Получите ответ:

```
{
  "data": {
    "register": {
      "access_token": "YOUR_ACCESS_TOKEN"
    }
  }
}
```

### Вход в систему

Отправьте POST-запрос с JSON-телом запроса:

```
mutation {
  login(
    email: 'user@example.com',
    password: 'password'
  ) {
    access_token
  }
}
```

Получите ответ:

```
{
  "data": {
    "login": {
      "access_token": "YOUR_ACCESS_TOKEN"
    }
  }
}
```

### Защищенные запросы

Для выполнения защищенного запроса, включите JWT-токен в заголовке запроса:

```
Authorization: Bearer YOUR_JWT_TOKEN
```

Для проверки аутентификации пользователя с использованием JWT-токена, переданного в заголовке запроса отправьте Get-запрос с телом: 

```
{
  auth {
    access_token
  }
}
```

Если запрос на защищенный ресурс выполнен успешно, сервер вернет токен доступа:

```
{
  "data": {
    "auth": {
      "access_token": "YOUR_ACCESS_TOKEN"
    }
  }
}
```

Если запрос на защищенный ресурс не выполнен, сервер вернет ошибку:

```
{
  "errors": [
    {
      "message": "Unauthorized",
      "locations": [
        {
          "line": 2,
          "column": 5
        }
      ],
      "path": [
        "auth"
      ]
    }
  ],
  "data": {
    "auth": null
  }
}
```

## Docker-контейнер

Вы также можете запустить сервер внутри Docker-контейнера.

Для создания Docker-образа выполните:

```
docker build -t имя_вашего_образа .
```

И для запуска контейнера:

```
docker run -p 8001:8001 --name имя_вашего_контейнера имя_вашего_образа
```
