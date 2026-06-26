/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */
import { type Request, type Response, type NextFunction } from 'express'
import config from 'config'

import * as challengeUtils from '../lib/challengeUtils'
import { challenges, users } from '../data/datacache'
import { BasketModel } from '../models/basket'
import * as security from '../lib/insecurity'
import { UserModel } from '../models/user'
import * as models from '../models/index'
import { type Challenge, type User } from '../data/types'
import * as utils from '../lib/utils'
import { loadStaticUserData } from '../data/staticData'

/* eslint-disable @stylistic/quote-props */
const LOGIN_CHALLENGES: Record<string, keyof typeof challenges> = {
  'admin': 'weakPasswordChallenge',
  'support': 'loginSupportChallenge',
  'mc.safesearch': 'loginRapperChallenge',
  'amy': 'loginAmyChallenge',
  'J12934': 'dlpPasswordSprayingChallenge',
  'bjoern.kimminich@gmail.com': 'oauthUserPasswordChallenge',
  'testing': 'exposedCredentialsChallenge',
}
/* eslint-enable @stylistic/quote-props */
let CHALLENGE_USER_PASSWORDS: Map<keyof typeof LOGIN_CHALLENGES, string> | null = null

async function loadUserPasswords (emails: string[]): Promise<Map<string, string>> {
  const users = await loadStaticUserData()
  const result = new Map<string, string>()

  for (const user of users) {
    if (emails.includes(user.email)) {
      result.set(user.email, user.password)
    }
  }

  return result
}

// vuln-code-snippet start loginAdminChallenge loginBenderChallenge loginJimChallenge
export function login () {
  function afterLogin (user: User, res: Response, next: NextFunction) {
    verifyPostLoginChallenges(user) // vuln-code-snippet hide-line
    BasketModel.findOrCreate({ where: { UserId: user.id } })
      .then(([basket]: [BasketModel, boolean]) => {
        const authenticatedUser = { data: user, bid: basket.id } // keep track of original basket
        const token = security.authorize(authenticatedUser)
        security.authenticatedUsers.put(token, authenticatedUser)
        res.json({ authentication: { token, bid: basket.id, umail: user.email } })
      }).catch((error: Error) => {
        next(error)
      })
  }

  return (req: Request, res: Response, next: NextFunction) => {
    verifyPreLoginChallenges(req) // vuln-code-snippet hide-line
    models.sequelize.query('SELECT * FROM Users WHERE email = $email AND password = $password AND deletedAt IS NULL', { model: UserModel, plain: true, bind: { email: req.body.email || '', password: security.hash(req.body.password || '') } }) // vuln-code-snippet vuln-line loginAdminChallenge loginBenderChallenge loginJimChallenge
      .then((authenticatedUser) => { // vuln-code-snippet neutral-line loginAdminChallenge loginBenderChallenge loginJimChallenge
        const user = utils.queryResultToJson(authenticatedUser)
        if (user.data?.id && user.data.totpSecret !== '') {
          res.status(401).json({
            status: 'totp_token_required',
            data: {
              tmpToken: security.authorize({
                userId: user.data.id,
                type: 'password_valid_needs_second_factor_token'
              })
            }
          })
        } else if (user.data?.id) {
          afterLogin(user.data, res, next)
        } else {
          res.status(401).send(res.__('Invalid email or password.'))
        }
      }).catch((error: Error) => {
        next(error)
      })
  }
  // vuln-code-snippet end loginAdminChallenge loginBenderChallenge loginJimChallenge

  async function verifyPreLoginChallenges (req: Request) {
    CHALLENGE_USER_PASSWORDS ??= await loadUserPasswords(Object.keys(LOGIN_CHALLENGES))

    const atDomain = `@${config.get<string>('application.domain')}`
    let email = req.body.email as string
    // remove local domain
    if (email.endsWith(atDomain)) {
      email = email.substring(0, email.length - atDomain.length)
      // if there's still a @ in the string, quit
      if (email.includes('@')) {
        return
      }
    }

    // try to get a password for the challenge user
    const expPassword = CHALLENGE_USER_PASSWORDS.get(email)
    if (expPassword === undefined) {
      return
    }
    challengeUtils.solveIf(challenges[LOGIN_CHALLENGES[email]], () => req.body.password === expPassword)
  }

  function verifyPostLoginChallenges (user: User) {
    challengeUtils.solveIf(challenges.loginAdminChallenge, () => { return user.id === users.admin.id })
    challengeUtils.solveIf(challenges.loginJimChallenge, () => { return user.id === users.jim.id })
    challengeUtils.solveIf(challenges.loginBenderChallenge, () => { return user.id === users.bender.id })
    challengeUtils.solveIf(challenges.ghostLoginChallenge, () => { return user.id === users.chris.id })
    if (challengeUtils.notSolved(challenges.ephemeralAccountantChallenge) && user.email === 'acc0unt4nt@' + config.get<string>('application.domain') && user.role === 'accounting') {
      UserModel.count({ where: { email: 'acc0unt4nt@' + config.get<string>('application.domain') } }).then((count: number) => {
        if (count === 0) {
          challengeUtils.solve(challenges.ephemeralAccountantChallenge)
        }
      }).catch(() => {
        throw new Error('Unable to verify challenges! Try again')
      })
    }
  }
}
