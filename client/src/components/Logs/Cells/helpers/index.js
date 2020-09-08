import { BLOCK_ACTIONS } from '../../../../helpers/constants';
import { convertDisallowedToEnum } from '../../../../helpers/helpers';

export const BUTTON_PREFIX = 'btn_';

// TODO: block when NOT_IN_ALLOWED_LIST
export const getBlockClientInfo = (client, disallowed) => {
    const disallowedState = convertDisallowedToEnum(disallowed);
    const type = disallowedState.isAllowed ? BLOCK_ACTIONS.BLOCK : BLOCK_ACTIONS.UNBLOCK;

    const confirmMessage = disallowedState.isAllowed ? 'client_confirm_block' : 'client_confirm_unblock';
    const buttonKey = disallowedState.isAllowed ? 'disallow_this_client' : 'allow_this_client';
    return {
        confirmMessage,
        buttonKey,
        type,
    };
};
