package ru.javabegin.micro.planner.users.mq.func;

import lombok.Getter;
import org.springframework.messaging.support.MessageBuilder;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Sinks;


// работа с каналами
@Service
@Getter
// помогает реализовать отправку сообщения с помощью функц. кода - по требованию (только после вызова соотв. метода)
public class MessageFuncActions {

    // каналы для обмена сообщениями
    private MessageFunc messageFunc;

    public MessageFuncActions(MessageFunc streamFunctions) {
        this.messageFunc = streamFunctions;
    }

    // отправка сообщения
    public void sendNewUserMessage(Long id) {
        // добавляем в слушатель новое сообщение
        messageFunc.getInnerBus().emitNext(MessageBuilder.withPayload(id).build(), Sinks.EmitFailureHandler.FAIL_FAST);
        System.out.println("Message sent: " + id);
    }


}
