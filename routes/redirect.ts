/*
 * Copyright (c) 2014-2025 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { type Request, type Response, type NextFunction } from 'express'

import * as challengeUtils from '../lib/challengeUtils'
import { challenges } from '../data/datacache'
import * as security from '../lib/insecurity'
import * as utils from '../lib/utils'

export function performRedirect () {
  return ({ query }: Request, res: Response, next: NextFunction) => {
    const toUrl: string = query.to as string
    // First, use the centralized helper as a fast-path check
    if (toUrl && security.isRedirectAllowed(toUrl)) {
      // Additional, explicit validation that CodeQL/SAST recognises:
      // parse the target URL and compare its origin to an allowlist of origins
      try {
        // allow application-relative redirects
        if (toUrl.startsWith('/')) {
          challengeUtils.solveIf(challenges.redirectCryptoCurrencyChallenge, () => { return toUrl === 'https://explorer.dash.org/address/Xr556RzuwX6hg5EGpkybbv5RanJoZN17kW' || toUrl === 'https://blockchain.info/address/1AbKfgvw9psQ41NbLi8kufDQTezwG8DRZm' || toUrl === 'https://etherscan.io/address/0x0f933ab9fcaaa782d0279c300d73750e1311eae6' })
          challengeUtils.solveIf(challenges.redirectChallenge, () => { return isUnintendedRedirect(toUrl) })
          res.redirect(toUrl)
        }

        const parsed = new URL(toUrl)
        // only allow http(s) schemes
        if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
          throw new Error('Unsupported protocol')
        }

        // derive allowed origins from the full-URL allowlist exported by `security`
        const allowedOrigins = new Set<string>()
        for (const allowedFullUrl of security.redirectAllowlist) {
          try {
            allowedOrigins.add(new URL(allowedFullUrl).origin)
          } catch (e) {
            // ignore invalid entries
          }
        }

        if (allowedOrigins.has(parsed.origin)) {
          challengeUtils.solveIf(challenges.redirectCryptoCurrencyChallenge, () => { return toUrl === 'https://explorer.dash.org/address/Xr556RzuwX6hg5EGpkybbv5RanJoZN17kW' || toUrl === 'https://blockchain.info/address/1AbKfgvw9psQ41NbLi8kufDQTezwG8DRZm' || toUrl === 'https://etherscan.io/address/0x0f933ab9fcaaa782d0279c300d73750e1311eae6' })
          challengeUtils.solveIf(challenges.redirectChallenge, () => { return isUnintendedRedirect(toUrl) })
          res.redirect(toUrl)
        }
      } catch (err) {
        // fall through to error handling below
      }
    }

    res.status(406)
    next(new Error('Unrecognized target URL for redirect: ' + toUrl))
  }
}

function isUnintendedRedirect (toUrl: string) {
  let unintended = true
  for (const allowedUrl of security.redirectAllowlist) {
    unintended = unintended && !utils.startsWith(toUrl, allowedUrl)
  }
  return unintended
}
