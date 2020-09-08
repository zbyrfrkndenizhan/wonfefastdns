import i18next from 'i18next';
import { convertDisallowedToEnum } from '../../../../helpers/helpers';

export const BUTTON_PREFIX = 'btn_';

export const getBlockClientInfo = (ip, disallowed) => {
    const disallowedState = convertDisallowedToEnum(disallowed);

    const confirmMessage = disallowedState.isAllowed
        ? `${i18next.t('adg_will_drop_dns_queries')} ${i18next.t('client_confirm_block', { ip })}`
        : i18next.t('client_confirm_unblock', { ip: disallowed });

    const buttonKey = i18next.t(disallowedState.isAllowed ? 'disallow_this_client' : 'allow_this_client');

    return {
        confirmMessage,
        buttonKey,
        // TODO: remove option when NOT_IN_ALLOWED_LIST
        // disabled: disallowedState.isNotInAllowedList,
    };
};
