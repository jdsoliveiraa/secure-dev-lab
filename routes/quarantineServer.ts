/*
 * Copyright (c) 2014-2025 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import path from 'node:path'
import fs from 'node:fs'
import { type Request, type Response, type NextFunction } from 'express'

export function serveQuarantineFiles () {
  return ({ params, query }: Request, res: Response, next: NextFunction) => {
    const file = String(params.file || '')

    // Basic checks to avoid obvious malicious input
    if (!file || file.includes('\0')) {
      res.status(400)
      next(new Error('Invalid file name'))
      return
    }

    const baseDir = path.resolve('ftp/quarantine')

    // Follow symlinks for both base and target to prevent symlink-based bypasses
    let realBase: string
    try {
      realBase = fs.realpathSync(baseDir)
    } catch (err) {
      // Base directory should exist. If it doesn't, fail safe.
      res.status(500)
      next(err as Error)
      return
    }

    const resolved = path.resolve(realBase, file)

    let realResolved: string
    try {
      realResolved = fs.realpathSync(resolved)
    } catch (err) {
      // If target doesn't exist, return 404
      res.status(404)
      next(new Error('Not found'))
      return
    }

    // Ensure the resolved (and symlink-resolved) path is still within the intended directory
    const insideBase = realResolved === realBase || realResolved.startsWith(realBase + path.sep)

    if (!insideBase) {
      res.status(403)
      next(new Error('Access denied'))
      return
    }

    // Only serve regular files (no directories, devices, etc.)
    try {
      const stat = fs.statSync(realResolved)
      if (!stat.isFile()) {
        res.status(404)
        next(new Error('Not found'))
        return
      }
    } catch (err) {
      res.status(404)
      next(new Error('Not found'))
      return
    }

    // Finally send the canonicalized, symlink-resolved file path
    res.sendFile(realResolved, (err) => {
      if (err) {
        next(err)
      }
    })
  }
}
