/* eslint-disable @typescript-eslint/no-unused-vars */
import { existsSync, mkdirSync, writeFileSync } from 'fs';

import CreateOperation from '../../lib/core/versions/latest/CreateOperation';
import ErrorCode from '../../lib/core/versions/latest/ErrorCode';
import JasmineSidetreeErrorValidator from '../JasmineSidetreeErrorValidator';
import Jwk from '../../lib/core/versions/latest/util/Jwk';
import Operation from '../../lib/core/versions/latest/Operation';
import OperationGenerator from '../generators/OperationGenerator';
import PatchAction from '../../lib/core/versions/latest/PatchAction';
import SidetreeError from '../../lib/common/SidetreeError';

describe('Operation', async () => {
  describe('parse()', async () => {
    it('should throw if operation of unknown type is given.', async (done) => {
      const operationOfUnknownType = {
        type: 'unknown',
        anyProperty: 'anyContent'
      };
      const operationBuffer = Buffer.from(JSON.stringify(operationOfUnknownType));

      await expectAsync(Operation.parse(operationBuffer)).toBeRejectedWith(new SidetreeError(ErrorCode.OperationTypeUnknownOrMissing));
      done();
    });
  });

  describe('validateDelta', () => {
    it('should throw sidetree error if input is not an object', () => {
      const input = 'this is not an object, this is a string';

      JasmineSidetreeErrorValidator.expectSidetreeErrorToBeThrown(
        () => Operation.validateDelta(input),
        ErrorCode.InputValidatorInputIsNotAnObject,
        'delta'
      );
    });
  });

  describe('generateVectors', () => {

    it('should do stuff and things', async () => {

      // Out directory
      const OUT_DIR = `${__dirname}/vectors`;
      if (!existsSync(OUT_DIR)) {
        mkdirSync(OUT_DIR);
      }

      // Stuff and things
      const signingKeyId = 'signingKey';
      const [recoveryPublicKey, recoveryPrivateKey] = await Jwk.generateEs256kKeyPair();
      const [updatePublicKey, updatePrivateKey] = await Jwk.generateEs256kKeyPair();
      const [signingPublicKey, signingPrivateKey] = await OperationGenerator.generateKeyPair(signingKeyId);
      const services = OperationGenerator.generateServices(['serviceId123']);

      expect(recoveryPrivateKey).toBeDefined();
      expect(updatePrivateKey).toBeDefined();
      expect(signingPrivateKey).toBeDefined();

      // First we make the create request
      const createRequest = await OperationGenerator.createCreateOperationRequest(
        recoveryPublicKey,
        updatePublicKey,
        [signingPublicKey],
        services
      );

      const operationBuffer = Buffer.from(JSON.stringify(createRequest));
      const createOperation = await CreateOperation.parse(operationBuffer);
      const { didUniqueSuffix } = createOperation;
      writeFileSync(`${OUT_DIR}/did`, didUniqueSuffix);
      writeFileSync(`${OUT_DIR}/create`, JSON.stringify(createRequest, null, 2));

      // Then we try the recover operation

      const document = { publicKeys: [] };
      const [anyNewRecoveryPublicKey] = await Jwk.generateEs256kKeyPair();
      const updateCommitment = createRequest.delta.updateCommitment;

      const recoverRequest = await OperationGenerator.createRecoverOperationRequest(
        didUniqueSuffix,
        recoveryPrivateKey,
        anyNewRecoveryPublicKey,
        updateCommitment,
        document
      );

      writeFileSync(`${OUT_DIR}/recover`, JSON.stringify(recoverRequest, null, 2));

      // Then we make the update request

      const patches = [
        {
          action: PatchAction.AddServices,
          services: [{
            id: 'someId',
            type: 'someType',
            serviceEndpoint: 'someEndpoint'
          }]
        }
      ];

      const updateRequest = await OperationGenerator.createUpdateOperationRequest(
        didUniqueSuffix,
        updatePublicKey,
        updatePrivateKey,
        updateCommitment,
        patches
      );

      writeFileSync(`${OUT_DIR}/update`, JSON.stringify(updateRequest, null, 2));

      // Then we write a deactivate command

      const deactivateOperationData = await OperationGenerator.createDeactivateOperation(didUniqueSuffix, recoveryPrivateKey);
      const deactivateRequest = deactivateOperationData.operationRequest;
      writeFileSync(`${OUT_DIR}/deactivate`, JSON.stringify(deactivateRequest, null, 2));

      // Write these to curl, so I don't have to manually make it

      const C = JSON.stringify(createRequest);
      const R = JSON.stringify(recoverRequest);
      const U = JSON.stringify(updateRequest);
      const D = JSON.stringify(deactivateRequest);

      const args = '--header "Content-Type: application/json" --request POST';
      const host = 'http://localhost:3000/operations';

      const curl = [
        `curl ${args} --data '${C}' ${host}`,
        `curl http://localhost:3000/identifiers/did:ion:${didUniqueSuffix}`,
        `curl ${args} --data '${R}' ${host}`,
        `curl http://localhost:3000/identifiers/did:ion:${didUniqueSuffix}`,
        `curl ${args} --data '${U}' ${host}`,
        `curl http://localhost:3000/identifiers/did:ion:${didUniqueSuffix}`,
        `curl ${args} --data '${D}' ${host}`,
        `curl http://localhost:3000/identifiers/did:ion:${didUniqueSuffix}`
      ].join('\n\n');
      writeFileSync(`${OUT_DIR}/curl`, curl);

    });
  });
});
