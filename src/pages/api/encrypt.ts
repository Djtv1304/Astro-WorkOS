// src/pages/api/encrypt.ts
import type { APIRoute } from "astro";
import { ClientSecretCredential } from "@azure/identity";
import { CryptographyClient, KeyClient } from "@azure/keyvault-keys";
import { Buffer } from "buffer";             // ↔️ Asegura la definición de Buffer

export const prerender = false;

export const GET: APIRoute = async () => {

    // 1. Credenciales y endpoint
    const credential = new ClientSecretCredential(
        import.meta.env.AZURE_TENANT_ID!,
        import.meta.env.AZURE_CLIENT_ID!,
        import.meta.env.AZURE_CLIENT_SECRET!
    );
    const vaultUrl= import.meta.env.AZURE_KEYVAULT_URL;
    const keyName    = "Software-Key";

    // 2. Obtener la clave y preparar CryptoClient
    const keyClient = new KeyClient(vaultUrl, credential);
    const key= await keyClient.getKey(keyName);

    if (!key.id) {
        return new Response("Error: key.id indefinido", { status: 500 });
    }

    const crypto = new CryptographyClient(key.id, credential);

    // 3. Datos “quemados”
    // const payload = JSON.stringify({ prueba: "Hola Astro", ts: Date.now() });
    const payload = JSON.stringify({
        vehicles: [
            {
                id: 1,
                type: "Sedan",
                rating: 4.8,
                name: "Tesla Model 3",
                rangeMiles: 358,
                seats: 5,
                pricePerDay: 89,
                features: ["Autopilot", "Premium Audio", "Supercharging"]
            },
        ]
    });

    // 4. Encriptar
    const encryptResult = await crypto.encrypt({
        algorithm: "RSA-OAEP",
        plaintext: Buffer.from(payload),
    });

    // 5. Convertir a Base64
    const ciphertext = Buffer.from(encryptResult.result).toString("base64");

    // 6. Devolver JSON
    return new Response(JSON.stringify({ ciphertext }), {
        status: 200,
        headers: { "Content-Type": "application/json" },
    });
};