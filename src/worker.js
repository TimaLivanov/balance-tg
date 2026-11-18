
export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    if (url.pathname === "/api/ai") {
      if (request.method !== "POST") {
        return Response.json(
          { error: "Method not allowed" },
          { status: 405 }
        );
      }

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

        const systemPrompt =
          "Ты финансовый AI-советник BitBalance. " +
          "Отвечай на русском языке. " +
          "Проверяй финансовые расчёты. " +
          "Не выдумывай доходы, расходы и долги. " +
          "Используй переданный контекст пользователя. " +
          "Если информации недостаточно, прямо скажи об этом.";

        const input =
          "ДАННЫЕ ПОЛЬЗОВАТЕЛЯ:\n" +
          context +
          "\n\nВОПРОС:\n" +
          question;

        const models = [
          "gemini-3.7-flash",
          "gemini-3.5-flash-lite"
        ];

        let lastError = "";

        for (const model of models) {
          let response;

          try {
            response = await fetch(
              "https://generativelanguage.googleapis.com/v1beta/interactions",
              {
                method: "POST",
                headers: {
                  "Content-Type": "application/json",
                  "x-goog-api-key": env.GEMINI_API_KEY
                },
                body: JSON.stringify({
                  model,
                  store: false,
                  system_instruction: systemPrompt,
                  input
                }),
                signal: AbortSignal.timeout(30000)
              }
            );
          } catch (error) {
            lastError = model + ": " + error.message;
            continue;
          }

          const raw = await response.text();

          let result;

          try {
            result = JSON.parse(raw);
          } catch {
            result = null;
          }

          if (!response.ok) {
            lastError =
              "Gemini " + model +
              " HTTP " + response.status +
              ": " +
              (
                result?.error?.message ||
                raw.slice(0, 1000)
              );

            if (
              [429, 500, 502, 503, 504].includes(
                response.status
              )
            ) {
              continue;
            }

            return Response.json(
              { error: lastError },
              { status: 502 }
            );
          }

          const answer = (result?.steps || [])
            .filter(step => step.type === "model_output")
            .flatMap(step => step.content || [])
            .filter(item => item.type === "text")
            .map(item => item.text || "")
            .join("\n")
            .trim();

          if (answer) {
            return Response.json(
              {
                answer,
                model
              },
              {
                headers: {
                  "Cache-Control": "no-store"
                }
              }
            );
          }

          lastError =
            "Модель " + model +
            " не вернула текстовый ответ";
        }

        return Response.json(
          {
            error:
              "Не удалось получить ответ от Gemini. " +
              lastError
          },
          { status: 502 }
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

    return env.ASSETS.fetch(request);
  }
};
