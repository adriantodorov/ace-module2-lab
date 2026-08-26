/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import fs from 'node:fs'
import { Readable } from 'node:stream'
import { finished } from 'node:stream/promises'
import { type Request, type Response, type NextFunction } from 'express'
import dns from 'node:dns'

import * as security from '../lib/insecurity'
import { UserModel } from '../models/user'
import * as utils from '../lib/utils'
import logger from '../lib/logger'

function isPrivateIp (ip: string): boolean {
  // Normalize IPv4-mapped IPv6 address
  if (ip.startsWith('::ffff:')) {
    ip = ip.substring(7)
  }

  // IPv4 validation
  const ipv4Regex = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/
  const ipv4Match = ip.match(ipv4Regex)
  if (ipv4Match) {
    const parts = ipv4Match.slice(1).map(Number)
    if (parts.some(part => part < 0 || part > 255)) {
      return true // Treat invalid octet as private/blocked to be safe
    }
    const [p1, p2, p3, p4] = parts

    // 127.0.0.0/8 (Loopback)
    if (p1 === 127) return true

    // 10.0.0.0/8 (Private)
    if (p1 === 10) return true

    // 172.16.0.0/12 (Private)
    if (p1 === 172 && p2 >= 16 && p2 <= 31) return true

    // 192.168.0.0/16 (Private)
    if (p1 === 192 && p2 === 168) return true

    // 169.254.0.0/16 (Link-local)
    if (p1 === 169 && p2 === 254) return true

    // 0.0.0.0/8 (Unspecified)
    if (p1 === 0) return true

    // 224.0.0.0/4 (Multicast) & 240.0.0.0/4 (Reserved)
    if (p1 >= 224) return true

    return false
  }

  // IPv6 validation
  const lowerIp = ip.toLowerCase()

  // Loopback (::1) and Unspecified (::)
  if (lowerIp === '::1' || lowerIp === '::' || lowerIp === '0:0:0:0:0:0:0:1' || lowerIp === '0:0:0:0:0:0:0:0') {
    return true
  }

  // Unique Local Address (ULA): fc00::/7 (fc00:: to fdff::)
  if (lowerIp.startsWith('fc') || lowerIp.startsWith('fd')) {
    return true
  }

  // Link-Local: fe80::/10 (fe80:: to febf::)
  if (lowerIp.startsWith('fe8') || lowerIp.startsWith('fe9') || lowerIp.startsWith('fea') || lowerIp.startsWith('feb')) {
    return true
  }

  return false
}

export function profileImageUrlUpload () {
  return async (req: Request, res: Response, next: NextFunction) => {
    if (req.body.imageUrl !== undefined) {
      const url = req.body.imageUrl
      if (url.match(/(.)*solve\/challenges\/server-side(.)*/) !== null) req.app.locals.abused_ssrf_bug = true
      const loggedInUser = security.authenticatedUsers.get(req.cookies.token)
      if (loggedInUser) {
        try {
          const parsedUrl = new URL(url)
          if (!['http:', 'https:'].includes(parsedUrl.protocol)) {
            throw new Error('Only HTTP and HTTPS protocols are allowed')
          }

          let hostname = parsedUrl.hostname
          if (hostname.startsWith('[') && hostname.endsWith(']')) {
            hostname = hostname.slice(1, -1)
          }

          if (hostname.toLowerCase() === 'localhost') {
            throw new Error('Access to localhost is not allowed')
          }

          let ip: string
          try {
            const lookupResult = await dns.promises.lookup(hostname)
            ip = lookupResult.address
          } catch (err) {
            throw new Error('Could not resolve hostname')
          }

          if (isPrivateIp(ip)) {
            throw new Error('Access to private/internal IP address is not allowed')
          }

          const response = await fetch(url)
          if (!response.ok || !response.body) {
            throw new Error('url returned a non-OK status code or an empty body')
          }
          const ext = ['jpg', 'jpeg', 'png', 'svg', 'gif'].includes(url.split('.').slice(-1)[0].toLowerCase()) ? url.split('.').slice(-1)[0].toLowerCase() : 'jpg'
          const fileStream = fs.createWriteStream(`frontend/dist/frontend/assets/public/images/uploads/${loggedInUser.data.id}.${ext}`, { flags: 'w' })
          await finished(Readable.fromWeb(response.body as any).pipe(fileStream))
          const user = await UserModel.findByPk(loggedInUser.data.id)
          await user?.update({ profileImage: `/assets/public/images/uploads/${loggedInUser.data.id}.${ext}` })
        } catch (error) {
          try {
            const user = await UserModel.findByPk(loggedInUser.data.id)
            await user?.update({ profileImage: url })
            logger.warn(`Error retrieving user profile image: ${utils.getErrorMessage(error)}; using image link directly`)
          } catch (error) {
            next(error)
            return
          }
        }
      } else {
        next(new Error('Blocked illegal activity by ' + req.socket.remoteAddress))
        return
      }
    }
    res.location(process.env.BASE_PATH + '/profile')
    res.redirect(process.env.BASE_PATH + '/profile')
  }
}
