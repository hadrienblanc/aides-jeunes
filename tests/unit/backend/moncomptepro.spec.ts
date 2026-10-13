import { expect, vi } from "vitest"
import jwt from "jsonwebtoken"
import { Request, Response } from "express"

vi.hoisted(() => {
  // Simule un déploiement où SESSION_SECRET n'est pas défini — ou laissé vide
  // comme dans .env.example (ligne 69 : `SESSION_SECRET=`) — auquel cas
  // backend/config/index.ts:129 retombe sur le littéral public du repo
  // "fghjdfjkdf785a-jreu". Une chaîne vide est falsy et dotenv n'écrase pas
  // une valeur déjà définie, donc ce réglage force déterministement le
  // fallback pour tout le graphe d'imports ci-dessous.
  process.env.SESSION_SECRET = ""
})

// Les modules suivants ne sont pas exercés par ce PoC ; on les mocke pour
// isoler le contrôleur (certains lisent des fichiers au chargement via
// import.meta.url, ce qui ne se comporte pas sous le transform vitest).
vi.mock("../../../backend/controllers/simulation.js", () => ({
  default: {},
}))
vi.mock("../../../backend/lib/mattermost-bot/poll-result.js", () => ({
  postPollResult: vi.fn(),
}))
vi.mock("../../../backend/lib/messaging/email/email-service.js", () => ({
  sendSimulationResultsEmail: vi.fn(),
}))
vi.mock("../../../backend/lib/messaging/sms/sms-service.js", () => ({
  sendSimulationResultsSms: vi.fn(),
}))
vi.mock("../../../data/all.js", () => ({
  default: { benefitsMap: {} },
}))

import moncompteproController from "../../../backend/controllers/moncomptepro.js"
import { showSurveyResultByEmail } from "../../../backend/controllers/followups.js"
import Followups from "../../../backend/models/followup.js"
import config from "../../../backend/config/index.js"

// Littéral public : présent en clair dans le repo (AGPL, GitHub public).
const PUBLIC_FALLBACK_SECRET = "fghjdfjkdf785a-jreu"

const buildAccessMocks = (mcpToken?: string) => {
  return {
    req: {
      cookies: mcpToken ? { mcp_token: mcpToken } : {},
      query: {}, // pas de query.code : aucune interaction ProConnect
    } as unknown as Request,
    res: {
      redirect: vi.fn(),
      clearCookie: vi.fn(),
    } as unknown as Response,
    next: vi.fn(),
  }
}

describe("SECURITY moncomptepro admin gate vs public fallback sessionSecret", () => {
  afterEach(() => {
    vi.restoreAllMocks()
  })

  it("precondition: without SESSION_SECRET, the backend signs/verifies with the public repo literal", () => {
    expect(config.sessionSecret).toBe(PUBLIC_FALLBACK_SECRET)
  })

  it("MUST reject an admin session JWT forged with the public repo secret (security regression)", async () => {
    // Attaquant : aucune interaction avec ProConnect. Il connaît le secret de
    // signature parce qu'il est committé en clair, et l'email autorisé parce
    // qu'il figure dans la allowlist du repo (user@yopmail.com hors production,
    // 3 emails beta.gouv en production).
    const attackerEmail = config.moncomptepro.authorized_email_users[0]
    const forgedMcpToken = jwt.sign(
      { email: attackerEmail },
      PUBLIC_FALLBACK_SECRET
    )

    const { req, res, next } = buildAccessMocks(forgedMcpToken)

    await moncompteproController.access(req, res, next)

    // Assertion de sécurité : moncompteproController.access protège
    // /api/followups/* et /api/support/* (données personnelles des usagers).
    // Un JWT signé avec un secret public ne doit JAMAIS y donner accès.
    // Ce test ÉCHOUE tant que la faille n'est pas corrigée : next() est
    // appelé alors que personne ne s'est authentifié auprès de ProConnect.
    expect(next).not.toHaveBeenCalled()
    expect(res.redirect).toHaveBeenCalled()
  })

  it("control: a token signed with any other secret is rejected (proves only the public literal is accepted)", async () => {
    const forgedMcpToken = jwt.sign(
      { email: config.moncomptepro.authorized_email_users[0] },
      "some-secret-not-in-the-repo"
    )

    const { req, res, next } = buildAccessMocks(forgedMcpToken)

    await moncompteproController.access(req, res, next)

    expect(next).not.toHaveBeenCalled()
    expect(res.redirect).toHaveBeenCalledWith(config.accompagnement.errorPath)
  })

  it("impact: behind the open gate, showSurveyResultByEmail returns full followup documents of other users", async () => {
    // Ce que l'attaquant lit sur GET /api/followups/email/:email une fois la
    // porte ouverte : documents Followup complets, sans projection.
    const victimFollowups = [
      {
        email: "victim@example.fr",
        phone: "0612345678",
        accessToken: "abc123def456ghi78", // capability de rebond vers les pages de suivi
        surveyOptin: true,
        benefits: [{ id: "rsa", montant: 565, unit: "month" }],
        surveys: [
          { type: "benefitAction", answers: [{ id: "rsa", value: "ok" }] },
        ],
        simulation: { _id: "646464646464646464646464" },
      },
    ]
    const findByEmailSpy = vi
      .spyOn(Followups, "findByEmail")
      .mockResolvedValue(victimFollowups as never)

    const req = { params: { email: "victim@example.fr" } } as unknown as Request
    const res = {
      send: vi.fn(),
      sendStatus: vi.fn(),
    } as unknown as Response

    await showSurveyResultByEmail(req, res)
    // showSurveyResultByEmail n'est pas async et ne retourne pas sa promesse :
    // on laisse la chaîne .then() interne se résoudre avant d'assertionner.
    await new Promise((resolve) => setTimeout(resolve, 0))

    expect(findByEmailSpy).toHaveBeenCalledWith("victim@example.fr")
    // Le document COMPLET est renvoyé : email, téléphone, accessToken.
    expect(res.send).toHaveBeenCalledWith(victimFollowups)
    expect(res.sendStatus).not.toHaveBeenCalled()
  })
})
