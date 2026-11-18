
export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    // API для AI
    if (url.pathname === "/api/ai") {
      if (request.method !== "POST") {
        return Response.json(
          { error: "Method not allowed" },
          { status: 405 }
        );
      }

      // Проверяем наличие ключа
      if (!env.GEMINI_API_KEY) {
        return Response.json(
          { error: "Не настроен GEMINI_API_KEY" },
          { status: 500 }
        );
      }

      try {
        const body = await request.json();

        const question = String(
          body.question || body.message || ""
        ).trim();

        const context = JSON.stringify(
          body.context || {}
        );

        if (!question) {
          return Response.json(
            { error: "Пустой вопрос" },
            { status: 400 }
          );
        }

        if (
          question.length > 5000 ||
          context.length > 30000
        ) {
          return Response.json(
            { error: "Слишком большой запрос" },
            { status: 413 }
          );
        }

        // Системные инструкции включаем прямо в input
        const systemPrompt =
          "Ты финансовый AI-советник BitBalance. " +
          "Отвечай на русском языке. " +
          "Проверяй финансовые расчёты. " +
          "Не выдумывай доходы, расходы и долги. " +
          "Используй переданный контекст пользователя. " +
          "Если информации недостаточно, прямо скажи об этом.";

        const input =
          systemPrompt +
          "\n\nДАННЫЕ ПОЛЬЗОВАТЕЛЯ:\n" +
          context +
          "\n\nВОПРОС ПОЛЬЗОВАТЕЛЯ:\n" +
          question;

        // Запрос к Gemini
        const response = await fetch(
          "https://generativelanguage.googleapis.com/v1beta/interactions",
          {
            method: "POST",
            headers: {
              "Content-Type": "application/json",
              "x-goog-api-key": env.GEMINI_API_KEY
            },
            body: JSON.stringify({
              model: "gemini-3.8-flash",
              store: false,
              input: input
            })
          }
        );

        // Читаем полный ответ Google
        const rawResponse = await response.text();

        let result;

        try {
          result = JSON.parse(rawResponse);
        } catch {
          result = null;
        }

        // Показываем настоящую ошибку Gemini
        if (!response.ok) {
          const googleError =
            result?.error?.message ||
            result?.message ||
            rawResponse ||
            "Google не вернул описание ошибки";

          return Response.json(
            {
              error:
                "Gemini API HTTP " +
                response.status +
                ": " +
                String(googleError).slice(0, 1200)
            },
            { status: 502 }
          );
        }

        if (!result) {
          return Response.json(
            {
              error:
                "Gemini вернул некорректный JSON: " +
                rawResponse.slice(0, 1000)
            },
            { status: 502 }
          );
        }

        // Извлекаем текст ответа
        const answer = (result.steps || [])
          .filter(step => step.type === "model_output")
          .flatMap(step => step.content || [])
          .filter(item => item.type === "text")
          .map(item => item.text || "")
          .join("\n")
          .trim();

        if (!answer) {
          return Response.json(
            {
              error:
                "Gemini не вернул текст. Статус: " +
                (result.status || "неизвестен")
            },
            { status: 502 }
          );
        }

        return Response.json(
          { answer },
          {
            headers: {
              "Cache-Control": "no-store"
            }
          }
        );

      } catch (error) {
        return Response.json(
          {
            error:
              "Ошибка Worker: " +
              String(error.message || error)
          },
          { status: 500 }
        );
      }
    }

    // Все остальные запросы обслуживает сайт
    return env.ASSETS.fetch(request);
  }
};
