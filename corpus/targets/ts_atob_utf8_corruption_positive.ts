export function decodeFileContent(data: { content: string, encoding: string }) {
  if (data.encoding === "base64") {
    data.content = atob(data.content);
  }
  return data.content;
}
