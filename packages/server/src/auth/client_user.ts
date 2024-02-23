import { badRequest, NewUserRequest, normalizeOperationOutcome } from '@medplum/core';
import { ClientApplication, User } from '@medplum/fhirtypes';
import { randomUUID } from 'crypto';
import { Request, Response } from 'express';
import { sendOutcome } from '../fhir/outcomes';
import { getSystemRepo } from '../fhir/repo';
import { getUserByEmailInProject, getUserByEmailWithoutProject, tryLogin } from '../oauth/utils';
import { createUser } from './newuser';

/**
 * Handles a HTTP request to /auth/register.
 * @param req - The HTTP request.
 * @param res - The HTTP response.
 */
export async function newUserClientHandler(req: Request, res: Response): Promise<void> {
  const systemRepo = getSystemRepo();

  let projectId = req.body.projectId as string | undefined;

  // If the user specifies a client ID, then make sure it is compatible with the project
  const clientId = req.body.clientId;
  let client: ClientApplication | undefined = undefined;
  if (!clientId) {
    sendOutcome(res, badRequest('ClientId is required', 'clientID'));
    return;
  }

  client = await systemRepo.readResource<ClientApplication>('ClientApplication', clientId);
  if (!client) {
    sendOutcome(res, badRequest('Invalid client', 'clientID'));
    return;
  }

  // If the user is a practitioner, then projectId should be undefined
  // If the user is a patient, then projectId must be set
  const email = req.body.email.toLowerCase();
  let existingUser = undefined;
  if (req.body.projectId && req.body.projectId !== 'new') {
    existingUser = await getUserByEmailInProject(email, req.body.projectId);
  } else {
    existingUser = (await getUserByEmailWithoutProject(email)) as User;
  }
  if (existingUser) {
    sendOutcome(res, badRequest('Email already registered', 'email'));
    return;
  }

  try {
    await createUser({ ...req.body, email } as NewUserRequest);

    const login = await tryLogin({
      authMethod: 'password',
      clientId,
      projectId,
      scope: req.body.scope || 'openid',
      nonce: req.body.nonce || randomUUID(),
      email,
      password: req.body.password,
      remember: req.body.remember,
      remoteAddress: req.body.client_ip,
      userAgent: req.body.client_user_agent,
      allowNoMembership: true,
    });
    res
      .status(200)
      .json({ client: { reference: `ClientApplication/${client.id}`, display: client.name }, login: login.id });
  } catch (err) {
    sendOutcome(res, normalizeOperationOutcome(err));
  }
}
