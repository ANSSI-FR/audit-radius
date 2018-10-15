# -*- coding: utf-8 -*-
"""
This module defines "utility" classes.
"""

from abc import ABCMeta, abstractmethod


class Observer(object):

    """
    Abstract base class from which every observer should inherit.
    """

    __metaclass__ = ABCMeta

    @abstractmethod
    def notify(self, event):

        """
        Notify an observer that an event has occurred.
        """

        pass


class Observable(object):

    """
    Abstract base class from which every "observable" object should inherit.
    """

    __metaclass__ = ABCMeta

    def __init__(self):
        self._observers = []

    def register(self, observer):

        """
        Add an observer to the observer list.
        """

        #if isinstance(observer, Observer) and observer not in self._observers:
        if observer not in self._observers:
            self._observers.append(observer)

    def unregister(self, observer):

        """
        Remove an observer from the observer list.
        """

        if observer in self._observers:
            self._observers.remove(observer)

    def unregister_all(self):

        """
        Remove all observers.
        """

        if self._observers:
            del self._observers[:]

    def notify_observers(self, event):

        """
        Notify the observers that an event has occurred.
        """

        for observer in self._observers:
            observer.notify(event)


class Event(object):

    """
    Abstract Event class.
    """

    __metaclass__ = ABCMeta

    def __init__(self, event_type=None, source=None):
        self._event_type = event_type
        self._source = source

    @property
    def event_type(self):

        """
        Return the event's type.
        """

        return self._event_type

    @property
    def source(self):

        """
        Return the source of the event.
        """

        return self._source

    def __str__(self):
        return "{}:{}".format(self._event_type, self._source)

    def __repr__(self):
        return str(self)


class FrameReceivedEvent(Event):

    """
    Event to be fired upon frame reception.
    """

    def __init__(
            self,
            event_type="FrameReceivedEvent",
            source=None,
    ):
        super(FrameReceivedEvent, self).__init__(
            event_type=event_type,
            source=source
        )


class TestResponseEvent(Event):

    """
    Event to be fired to notify that a response (not an EAP reponse packet :
    this can be an EAP Request, or an EAP Failure) has been obtained.
    """

    def __init__(
            self,
            event_type="TestResponseEvent",
            source=None,
            test_response=None,
    ):
        super(TestResponseEvent, self).__init__(
            event_type=event_type,
            source=source
        )
        self._test_response = test_response

    @property
    def test_response(self):

        """
        Return True if the event is a test response.
        """

        return self._test_response
