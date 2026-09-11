export function decodeFileContent(data: { content: string, encoding: string }) {
  if (data.encoding === "base64") {
    data.content = Buffer.from(data.content, "base64").toString("utf-8");
  }
  return data.content;
}
